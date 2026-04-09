use proptest::prelude::*;
use samp::*;

fn br(b: u32, i: u16) -> BlockRef {
    BlockRef::from_parts(b, i)
}

proptest! {
    #[test]
    fn encode_public_any_input_decode_roundtrips(
        recipient_bytes in prop::array::uniform32(any::<u8>()),
        body in "[\\x20-\\x7e]{0,256}",
    ) {
        let recipient = Pubkey::from_bytes(recipient_bytes);
        let remark = encode_public(&recipient, &body);
        let Remark::Public { recipient: r, body: b } = decode_remark(&remark).unwrap() else {
            panic!("expected Public");
        };
        prop_assert_eq!(r, recipient);
        prop_assert_eq!(b, body);
    }

    #[test]
    fn encode_channel_msg_any_refs_decode_roundtrips(
        ch_block in any::<u32>(), ch_idx in any::<u16>(),
        rt_block in any::<u32>(), rt_idx in any::<u16>(),
        ct_block in any::<u32>(), ct_idx in any::<u16>(),
        body in "[\\x20-\\x7e]{0,256}",
    ) {
        let remark = encode_channel_msg(
            br(ch_block, ch_idx),
            br(rt_block, rt_idx),
            br(ct_block, ct_idx),
            &body,
        );
        let parsed = decode_remark(&remark).unwrap();
        assert!(matches!(parsed, Remark::Channel { .. }));
    }

    #[test]
    fn encode_channel_create_valid_names_decode_roundtrips(
        name in "[a-z]{1,32}",
        desc in "[a-z]{0,128}",
    ) {
        let name_typed = ChannelName::parse(name.clone()).unwrap();
        let desc_typed = ChannelDescription::parse(desc.clone()).unwrap();
        let remark = encode_channel_create(&name_typed, &desc_typed);
        let Remark::ChannelCreate { name: n, description: d } = decode_remark(&remark).unwrap() else {
            panic!("expected ChannelCreate");
        };
        prop_assert_eq!(n.as_str(), name.as_str());
        prop_assert_eq!(d.as_str(), desc.as_str());
    }

    #[test]
    fn channel_name_over_32_returns_error(
        name in "[a-z]{33,64}",
    ) {
        prop_assert!(ChannelName::parse(name).is_err());
    }

    #[test]
    fn channel_description_over_128_returns_error(
        desc in "[a-z]{129,256}",
    ) {
        prop_assert!(ChannelDescription::parse(desc).is_err());
    }

    #[test]
    fn any_encode_output_has_samp_version_nibble(
        recipient_bytes in prop::array::uniform32(any::<u8>()),
        body in "[\\x20-\\x7e]{0,64}",
    ) {
        let recipient = Pubkey::from_bytes(recipient_bytes);
        let remark = encode_public(&recipient, &body);
        prop_assert_eq!(remark.as_bytes()[0] & 0xF0, 0x10);
    }

    #[test]
    fn encode_group_any_capsules_decode_roundtrips(
        nonce_bytes in prop::array::uniform::<_, 12>(any::<u8>()),
        eph_pubkey_bytes in prop::array::uniform32(any::<u8>()),
        n_capsules in 1..10usize,
        ct_len in 16..128usize,
    ) {
        let nonce = Nonce::from_bytes(nonce_bytes);
        let eph_pubkey = EphPubkey::from_bytes(eph_pubkey_bytes);
        let capsules = samp::Capsules::from_bytes(vec![0u8; n_capsules * 33]).unwrap();
        let ciphertext = samp::Ciphertext::from_bytes(vec![0u8; ct_len]);
        let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
        let Remark::Group(payload) = decode_remark(&remark).unwrap() else {
            panic!("expected Group");
        };
        prop_assert_eq!(payload.nonce, nonce);
    }

    #[test]
    fn encode_thread_content_any_refs_decode_roundtrips(
        t_block in any::<u32>(), t_idx in any::<u16>(),
        r_block in any::<u32>(), r_idx in any::<u16>(),
        c_block in any::<u32>(), c_idx in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let encoded = encode_thread_content(
            br(t_block, t_idx),
            br(r_block, r_idx),
            br(c_block, c_idx),
            &body,
        );
        let (thread, reply_to, continues, decoded_body) = decode_thread_content(&encoded).unwrap();
        prop_assert_eq!(thread, br(t_block, t_idx));
        prop_assert_eq!(reply_to, br(r_block, r_idx));
        prop_assert_eq!(continues, br(c_block, c_idx));
        prop_assert_eq!(decoded_body, body.as_slice());
    }
}
