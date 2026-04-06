use proptest::prelude::*;
use samp::*;

proptest! {
    #[test]
    fn encode_public_any_input_decode_roundtrips(
        recipient in prop::array::uniform32(any::<u8>()),
        body in "[\\x20-\\x7e]{0,256}",
    ) {
        let remark = encode_public(&recipient, body.as_bytes());
        let parsed = decode_remark(&remark).unwrap();
        prop_assert_eq!(parsed.recipient, recipient);
        prop_assert_eq!(parsed.content, body.as_bytes());
    }

    #[test]
    fn encode_channel_msg_any_refs_decode_roundtrips(
        ch_block in any::<u32>(), ch_idx in any::<u16>(),
        rt_block in any::<u32>(), rt_idx in any::<u16>(),
        ct_block in any::<u32>(), ct_idx in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let remark = encode_channel_msg(
            BlockRef { block: ch_block, index: ch_idx },
            BlockRef { block: rt_block, index: rt_idx },
            BlockRef { block: ct_block, index: ct_idx },
            &body,
        );
        let parsed = decode_remark(&remark).unwrap();
        assert!(matches!(parsed.content_type, ContentType::Channel));
    }

    #[test]
    fn encode_channel_create_valid_names_decode_roundtrips(
        name in "[a-z]{1,32}",
        desc in "[a-z]{0,128}",
    ) {
        let remark = encode_channel_create(&name, &desc).unwrap();
        let parsed = decode_remark(&remark).unwrap();
        let (n, d) = decode_channel_create(&parsed.content).unwrap();
        prop_assert_eq!(n, name.as_str());
        prop_assert_eq!(d, desc.as_str());
    }

    #[test]
    fn encode_channel_create_name_over_32_returns_error(
        name in "[a-z]{33,64}",
    ) {
        prop_assert!(encode_channel_create(&name, "").is_err());
    }

    #[test]
    fn encode_channel_create_desc_over_128_returns_error(
        desc in "[a-z]{129,256}",
    ) {
        prop_assert!(encode_channel_create("ok", &desc).is_err());
    }

    #[test]
    fn any_encode_output_has_samp_version_nibble(
        recipient in prop::array::uniform32(any::<u8>()),
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let remark = encode_public(&recipient, &body);
        prop_assert_eq!(remark[0] & 0xF0, 0x10);
    }

    #[test]
    fn encode_group_any_capsules_decode_roundtrips(
        nonce in prop::array::uniform::<_, 12>(any::<u8>()),
        eph_pubkey in prop::array::uniform32(any::<u8>()),
        n_capsules in 1..10usize,
        ct_len in 16..128usize,
    ) {
        let capsules = vec![0u8; n_capsules * 33];
        let ciphertext = vec![0u8; ct_len];
        let remark = encode_group(&nonce, &eph_pubkey, &capsules, &ciphertext);
        let parsed = decode_remark(&remark).unwrap();
        assert!(matches!(parsed.content_type, ContentType::Group));
        prop_assert_eq!(&parsed.nonce, &nonce);
    }

    #[test]
    fn encode_thread_content_any_refs_decode_roundtrips(
        t_block in any::<u32>(), t_idx in any::<u16>(),
        r_block in any::<u32>(), r_idx in any::<u16>(),
        c_block in any::<u32>(), c_idx in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let encoded = encode_thread_content(
            BlockRef { block: t_block, index: t_idx },
            BlockRef { block: r_block, index: r_idx },
            BlockRef { block: c_block, index: c_idx },
            &body,
        );
        let (thread, reply_to, continues, decoded_body) = decode_thread_content(&encoded).unwrap();
        prop_assert_eq!(thread, BlockRef { block: t_block, index: t_idx });
        prop_assert_eq!(reply_to, BlockRef { block: r_block, index: r_idx });
        prop_assert_eq!(continues, BlockRef { block: c_block, index: c_idx });
        prop_assert_eq!(decoded_body, body.as_slice());
    }
}
