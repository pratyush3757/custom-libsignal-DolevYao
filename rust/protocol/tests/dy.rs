mod support;

use hex_literal::hex;
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;

use std::time::{Duration, SystemTime};
use support::*;

use libsignal_protocol::*;
use rand::seq::SliceRandom;
use rand::Rng;

use uuid::Uuid;

type TestResult = Result<(), SignalProtocolError>;

// Use this function to debug tests
#[allow(dead_code)]
fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

#[test]
fn test_basic_prekey_once() -> TestResult {
    run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
        },
        PRE_KYBER_MESSAGE_VERSION,
    )?;

    fn run<F>(bob_add_keys: F, expected_session_version: u32) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            init_logger();
            let mut csprng = OsRng;

            let bob_device_id: DeviceId = 1.into();

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

            log::trace!("Build store for Bob");
            let mut bob_store_builder = TestStoreBuilder::new();
            log::trace!("Create Bob's store keys");
            bob_add_keys(&mut bob_store_builder);

            log::trace!("Build store for Alice");
            let mut alice_store_builder = TestStoreBuilder::new();
            let alice_store = &mut alice_store_builder.store;

            log::trace!("Make Bob preKey bundle");
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

            log::trace!("Alice processes Bob's bundle");
            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            let bobs_response = "Who watches the watchers?";

            assert!(bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .is_some());
            let bobs_session_with_alice = bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .expect("session found");
            assert_eq!(
                bobs_session_with_alice.session_version()?,
                expected_session_version
            );
            assert_eq!(bobs_session_with_alice.alice_base_key()?.len(), 32 + 1);

            log::trace!("Bob -> Alice Whisper");
            let bob_outgoing =
                encrypt(&mut bob_store_builder.store, &alice_address, bobs_response).await?;

            assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

            let alice_decrypts = decrypt(alice_store, &bob_address, &bob_outgoing).await?;

            {
                let record_len = alice_store.session_store.load_session(&bob_address).await
                    .expect("can load session")
                    .expect("has session record")
                    .serialize()
                    .expect("can serialize session record")
                    .len();
                assert!(1024 > record_len, "Unexpectedly large session record ({record_len} bytes). Did you forget to clean things up?")
            }


            assert_eq!(
                String::from_utf8(alice_decrypts).expect("valid utf8"),
                bobs_response
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }
    Ok(())
}


async fn run_interaction(
    alice_store: &mut InMemSignalProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &mut InMemSignalProtocolStore,
    bob_address: &ProtocolAddress,
) -> TestResult {
    let alice_ptext = "It's rabbit season";

    let alice_message = encrypt(alice_store, bob_address, alice_ptext).await?;
    assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
            .expect("valid utf8"),
        alice_ptext
    );

    let bob_ptext = "It's duck season";

    let bob_message = encrypt(bob_store, alice_address, bob_ptext).await?;
    assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
            .expect("valid utf8"),
        bob_ptext
    );

    for i in 0..3 {
        let alice_ptext = format!("A->B message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..3 {
        let bob_ptext = format!("B->A message {}", i);
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    Ok(())
}

#[test]
fn test_double_ratchet_dy() -> TestResult {
    run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
        },
        PRE_KYBER_MESSAGE_VERSION,
    )?;

    fn run<F>(bob_add_keys: F, expected_session_version: u32) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            init_logger();
            let mut csprng = OsRng;

            let bob_device_id: DeviceId = 1.into();

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

            log::trace!("Build store for Bob");
            let mut bob_store_builder = TestStoreBuilder::new();
            log::trace!("Create Bob's store keys");
            bob_add_keys(&mut bob_store_builder);

            log::trace!("Build store for Alice");
            let mut alice_store_builder = TestStoreBuilder::new();
            let alice_store = &mut alice_store_builder.store;

            log::trace!("Make Bob preKey bundle");
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

            log::trace!("Alice processes Bob's bundle");
            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            let bobs_response = "Who watches the watchers?";

            assert!(bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .is_some());
            let bobs_session_with_alice = bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .expect("session found");
            assert_eq!(
                bobs_session_with_alice.session_version()?,
                expected_session_version
            );
            assert_eq!(bobs_session_with_alice.alice_base_key()?.len(), 32 + 1);

            log::trace!("Bob -> Alice Whisper");
            let bob_outgoing =
                encrypt(&mut bob_store_builder.store, &alice_address, bobs_response).await?;

            assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

            let alice_decrypts = decrypt(alice_store, &bob_address, &bob_outgoing).await?;

            {
                let record_len = alice_store.session_store.load_session(&bob_address).await
                    .expect("can load session")
                    .expect("has session record")
                    .serialize()
                    .expect("can serialize session record")
                    .len();
                assert!(1024 > record_len, "Unexpectedly large session record ({record_len} bytes). Did you forget to clean things up?")
            }


            assert_eq!(
                String::from_utf8(alice_decrypts).expect("valid utf8"),
                bobs_response
            );

            run_interaction(
                alice_store,
                &alice_address,
                &mut bob_store_builder.store,
                &bob_address,
            )
            .await?;

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }
    Ok(())
}

#[test]
fn group_sealed_sender_dy() -> Result<(), SignalProtocolError> {
    async {
        init_logger();
        let mut csprng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();
        let carol_device_id: DeviceId = 1.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();
        let carol_uuid = "38381c3b-2606-4ca7-9310-7cb927f2ab4a".to_string();

        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), alice_device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);
        let carol_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol_device_id);

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        log::trace!("[Alice] KeyPair");
        let mut alice_store = support::test_in_memory_protocol_store()?;
        log::trace!("[Bob] KeyPair");
        let mut bob_store = support::test_in_memory_protocol_store()?;
        log::trace!("[Carol] KeyPair");
        let mut carol_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        log::trace!("[Bob] create_pre_key_bundle");
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;
        log::trace!("[Carol] create_pre_key_bundle");
        let carol_pre_key_bundle = create_pre_key_bundle(&mut carol_store, &mut csprng).await?;

        log::trace!("[Alice] process Bob's prekey bundle");
        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        log::trace!("[Alice] process Carol's prekey bundle");
        process_prekey_bundle(
            &carol_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        log::trace!("[Alice] create sender key dist message");
        let sent_distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        log::trace!("[Bob] process Alice sender key dist message");
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;
        log::trace!("[Carol] process Alice sender key dist message");
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol_store,
        )
        .await?;

        log::trace!("Create trust root and server key");
        let trust_root = KeyPair::generate(&mut csprng);
        let server_key = KeyPair::generate(&mut csprng);

        log::trace!("Create server cert");
        let server_cert = ServerCertificate::new(
            1,
            server_key.public_key,
            &trust_root.private_key,
            &mut csprng,
        )?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        log::trace!("Create sender cert");
        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut csprng,
        )?;

        log::trace!("[Alice] group encrypt message");
        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        log::trace!("[Alice] create usmc");
        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Implicit,
            Some([42].to_vec()),
        )?;

        let recipients = [&bob_uuid_address, &carol_uuid_address];
        log::trace!("[Alice] sealed sender group encrypt for Bob + Carol");
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;

        log::trace!("Asserts");
        let alice_ctext_parsed = SealedSenderV2SentMessage::parse(&alice_ctext)?;
        assert_eq!(alice_ctext_parsed.recipients.len(), 2);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(0)
                .expect("checked length")
                .0
                .service_id_string(),
            bob_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[0].devices.len(), 1);
        assert_eq!(alice_ctext_parsed.recipients[0].devices[0].0, bob_device_id);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(1)
                .expect("checked length")
                .0
                .service_id_string(),
            carol_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[1].devices.len(), 1);
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[0].0,
            carol_device_id
        );

        let bob_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[0])
            .as_ref()
            .concat();
        let carol_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[1])
            .as_ref()
            .concat();

        log::trace!("[Bob] sealed_sender_decrypt_to_usmc");
        let bob_usmc = sealed_sender_decrypt_to_usmc(&bob_ctext, &bob_store.identity_store).await?;

        assert_eq!(bob_usmc.sender()?.sender_uuid()?, alice_uuid);
        assert_eq!(bob_usmc.sender()?.sender_e164()?, Some(alice_e164.as_ref()));
        assert_eq!(bob_usmc.sender()?.sender_device_id()?, alice_device_id);
        assert_eq!(bob_usmc.content_hint()?, ContentHint::Implicit);
        assert_eq!(bob_usmc.group_id()?, Some(&[42][..]));

        log::trace!("[Bob] group decrypt usmc");
        let bob_plaintext =
            group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "space camp?"
        );

        log::trace!("[Carol] sealed_sender_decrypt_to_usmc");
        let carol_usmc =
            sealed_sender_decrypt_to_usmc(&carol_ctext, &carol_store.identity_store).await?;

        assert_eq!(carol_usmc.serialized()?, bob_usmc.serialized()?);

        log::trace!("[Carol] group decrypt usmc");
        let carol_plaintext = group_decrypt(
            carol_usmc.contents()?,
            &mut carol_store,
            &alice_uuid_address,
        )
        .await?;

        assert_eq!(
            String::from_utf8(carol_plaintext).expect("valid utf8"),
            "space camp?"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}
