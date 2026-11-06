//! Server-typed query parameters.
//!
//! `tokio_postgres` resolves parameter types at prepare time and then
//! refuses to bind a Rust `&str` to a non-string column (`&str` only
//! `accepts` the textual types), so a statement like
//! `WHERE "pk" = $1` against a `uuid`/`bigint` column cannot take a raw
//! string parameter. [`UntypedTextParam`] closes that gap: it accepts
//! whatever type the server inferred and sends the string in **text
//! format**, so `PostgreSQL` coerces it with the target type's input
//! function — exactly how the TS reference backend's `pg` driver
//! transmits every parameter. Invalid input surfaces as the usual
//! SQLSTATEs (`22P02` invalid text representation, `22003` numeric
//! value out of range) for the caller to classify.

use bytes::BytesMut;
use tokio_postgres::types::{Format, IsNull, ToSql, Type};

/// A string parameter bound in text format to whatever type the server
/// inferred for its placeholder.
///
/// Use when the target column's type is only known at runtime (e.g. a
/// primary key resolved from `information_schema`) and the value arrives
/// as a string: the server, not the client, converts — matching the TS
/// backend's semantics, where the `pg` driver sends all parameters
/// untyped in text format.
#[derive(Debug)]
pub struct UntypedTextParam<'a>(pub &'a str);

impl ToSql for UntypedTextParam<'_> {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        out.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }

    fn accepts(_ty: &Type) -> bool {
        // the server coerces the text-format value; any inferred type works
        true
    }

    fn encode_format(&self, _ty: &Type) -> Format {
        // the load-bearing override: text format makes the server run the
        // target type's input function on the raw string (binary would be
        // decoded as the inferred type's binary representation and fail)
        Format::Text
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        // `accepts` is unconditionally true, so no type check to perform
        self.to_sql(ty, out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_any_inferred_type() {
        assert!(UntypedTextParam::accepts(&Type::UUID));
        assert!(UntypedTextParam::accepts(&Type::INT8));
        assert!(UntypedTextParam::accepts(&Type::TEXT));
        assert!(UntypedTextParam::accepts(&Type::BYTEA));
    }

    #[test]
    fn encodes_the_raw_string_in_text_format() {
        let param = UntypedTextParam("a3bb189e-8bf9-3888-9912-ace4e6543002");
        let mut out = BytesMut::new();
        let is_null = param.to_sql(&Type::UUID, &mut out).unwrap();
        assert!(matches!(is_null, IsNull::No));
        assert_eq!(&out[..], b"a3bb189e-8bf9-3888-9912-ace4e6543002");
        // the load-bearing override — binary format would be decoded as the
        // inferred type's binary representation and fail
        assert!(matches!(param.encode_format(&Type::UUID), Format::Text));
        assert!(matches!(param.encode_format(&Type::INT8), Format::Text));
    }

    #[test]
    fn to_sql_checked_encodes_without_a_type_gate() {
        let param = UntypedTextParam("7");
        let mut out = BytesMut::new();
        let is_null = param.to_sql_checked(&Type::INT8, &mut out).unwrap();
        assert!(matches!(is_null, IsNull::No));
        assert_eq!(&out[..], b"7");
    }
}
