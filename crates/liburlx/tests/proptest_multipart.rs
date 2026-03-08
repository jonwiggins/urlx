//! Property-based tests for multipart form-data encoding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use liburlx::MultipartForm;

proptest! {
    /// A form with N fields encodes all field names and values.
    #[test]
    fn all_fields_present(n in 1usize..20) {
        let mut form = MultipartForm::with_boundary("test-boundary");
        let mut fields: Vec<(String, String)> = Vec::new();
        for i in 0..n {
            let name = format!("field{i}");
            let value = format!("value{i}");
            form.field(&name, &value);
            fields.push((name, value));
        }

        let body = String::from_utf8(form.encode()).unwrap();
        for (name, value) in &fields {
            prop_assert!(
                body.contains(&format!("name=\"{name}\"")),
                "missing field name: {name}"
            );
            prop_assert!(body.contains(value), "missing field value: {value}");
        }
    }

    /// Encoded form always ends with the closing boundary.
    #[test]
    fn always_ends_with_closing_boundary(
        n in 0usize..10,
        boundary in "[a-zA-Z0-9]{1,20}"
    ) {
        let mut form = MultipartForm::with_boundary(&boundary);
        for i in 0..n {
            form.field(&format!("f{i}"), &format!("v{i}"));
        }
        let body = String::from_utf8(form.encode()).unwrap();
        let expected_end = format!("--{boundary}--\r\n");
        prop_assert!(body.ends_with(&expected_end), "missing closing boundary");
    }

    /// Content-Type includes the boundary.
    #[test]
    fn content_type_includes_boundary(boundary in "[a-zA-Z0-9]{1,30}") {
        let form = MultipartForm::with_boundary(&boundary);
        let ct = form.content_type();
        prop_assert!(ct.contains(&boundary));
        prop_assert!(ct.starts_with("multipart/form-data; boundary="));
    }

    /// File data is present in the encoded body.
    #[test]
    fn file_data_present(
        data in proptest::collection::vec(any::<u8>(), 1..200),
    ) {
        let mut form = MultipartForm::with_boundary("b");
        form.file_data("file", "test.bin", &data);
        let body = form.encode();
        // The data should appear somewhere in the body
        prop_assert!(
            body.windows(data.len()).any(|w| w == data.as_slice()),
            "file data not found in encoded body"
        );
    }

    /// Field values with special characters are preserved.
    #[test]
    fn special_chars_preserved(value in "[a-zA-Z0-9!@#$%^&*()_+=-]{1,50}") {
        let mut form = MultipartForm::with_boundary("b");
        form.field("test", &value);
        let body = String::from_utf8(form.encode()).unwrap();
        prop_assert!(body.contains(&value));
    }
}
