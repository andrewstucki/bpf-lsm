mod compiler {
    use probe_sys::BpfQueryWriterFactory;
    use rule_compiler::compile;

    #[test]
    fn test_error_missing_fields() {
        let rule = compile(r#"REJECT bprm_check_security WHEN x==1 and y==2 AND z==3 OR x==1 AND y==2 OR x==1 and y==2 and z==3 and a=="2""#).unwrap();
        assert!(rule.encode(&BpfQueryWriterFactory::empty()).is_err());
    }

    #[test]
    fn test_error_type_mismatch() {
        let rule = compile(r#"REJECT bprm_check_security WHEN user.id == "test""#).unwrap();
        assert!(rule.encode(&BpfQueryWriterFactory::empty()).is_err());
    }

    #[test]
    fn test_error_repeated() {
        let rule = compile(r#"REJECT bprm_check_security WHEN user.id == "a" and user.id != "b""#)
            .unwrap();
        assert!(rule.encode(&BpfQueryWriterFactory::empty()).is_err());
    }

    #[test]
    fn test_ok() {
        let rule =
            compile(r#"REJECT bprm_check_security WHEN process.name == "ls" and user.id == 1"#)
                .unwrap();
        assert!(rule.encode(&BpfQueryWriterFactory::empty()).is_ok());
    }
}
