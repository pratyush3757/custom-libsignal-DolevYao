mod support;

use hex_literal::hex;
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;

use std::time::{Duration, SystemTime};
use support::*;

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

    /* run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        KYBER_AWARE_MESSAGE_VERSION,
    )?; */

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

            /* run_interaction(
                alice_store,
                &alice_address,
                &mut bob_store_builder.store,
                &bob_address,
            )
            .await?; */

            /* let mut alter_alice_store = TestStoreBuilder::new().store;

            bob_add_keys(&mut bob_store_builder);

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);
            process_prekey_bundle(
                &bob_address,
                &mut alter_alice_store.session_store,
                &mut alter_alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            let outgoing_message =
                encrypt(&mut alter_alice_store, &bob_address, original_message).await?;

            assert!(matches!(
                decrypt(&mut bob_store_builder.store, &alice_address, &outgoing_message)
                    .await
                    .unwrap_err(),
                SignalProtocolError::UntrustedIdentity(a) if a == alice_address
            ));

            assert!(
                bob_store_builder
                    .store
                    .save_identity(
                        &alice_address,
                        alter_alice_store
                            .get_identity_key_pair()
                            .await?
                            .identity_key(),
                    )
                    .await?
            );

            let decrypted = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &outgoing_message,
            )
            .await?;
            assert_eq!(
                String::from_utf8(decrypted).expect("valid utf8"),
                original_message
            );

            // Sign pre-key with wrong key:
            let bad_bob_pre_key_bundle = bob_store_builder
                .make_bundle_with_latest_keys(bob_device_id)
                .modify(|content| {
                    let wrong_identity = alter_alice_store
                        .get_identity_key_pair()
                        .now_or_never()
                        .expect("sync")
                        .expect("has identity key");
                    content.identity_key = Some(*wrong_identity.identity_key());
                })
                .expect("can reconstruct the bundle");

            assert!(process_prekey_bundle(
                &bob_address,
                &mut alter_alice_store.session_store,
                &mut alter_alice_store.identity_store,
                &bad_bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await
            .is_err()); */

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

    // let i: usize = 0;
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

    /* let mut alice_ooo_messages = vec![];

    for i in 0..10 {
        let alice_ptext = format!("A->B OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message post-OOO {}", i);
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    for (ptext, ctext) in alice_ooo_messages {
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &ctext).await?)
                .expect("valid utf8"),
            ptext
        );
    } */

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

