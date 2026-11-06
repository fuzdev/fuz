//! Queries against the single-row `app_settings` table.

use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

use crate::app_settings_schema::AppSettings;

/// The `app_settings` table's columns.
///
/// Twin of `fuz_app`'s `APP_SETTINGS_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column.
pub const APP_SETTINGS_COLUMNS: [&str; 4] = ["id", "open_signup", "updated_at", "updated_by"];

/// The [`AppSettingsWithUsername`] projection — [`APP_SETTINGS_COLUMNS`]
/// qualified by `alias` with `updated_at` as the ISO-8601 wire string; the
/// read appends the joined actor name after it. Decoded positionally by
/// [`decode_app_settings_with_username_row`].
fn app_settings_columns(alias: &str) -> String {
    qualify_columns(
        &APP_SETTINGS_COLUMNS,
        alias,
        iso8601_timestamp_expr(&APP_SETTINGS_COLUMNS, &["updated_at"], alias),
    )
}

/// Decode [`app_settings_columns`] + the trailing joined actor name
/// positionally (`id` at 0 is the constant `1` and isn't carried).
fn decode_app_settings_with_username_row(row: &tokio_postgres::Row) -> AppSettingsWithUsername {
    AppSettingsWithUsername {
        open_signup: row.get(col!(APP_SETTINGS_COLUMNS, "open_signup")),
        updated_at: row.get(col!(APP_SETTINGS_COLUMNS, "updated_at")),
        updated_by: row.get(col!(APP_SETTINGS_COLUMNS, "updated_by")),
        updated_by_username: row.get(APP_SETTINGS_COLUMNS.len()),
    }
}

/// App settings with the resolved username of the last updater.
///
/// Wire-equivalent to `AppSettingsWithUsernameJson` in `fuz_app`. The
/// `updated_at` field serializes as an ISO-8601 UTC string (or `null`
/// when the row has never been updated); `updated_by` is the actor UUID
/// (or `null`); `updated_by_username` is the actor name (or `null` when
/// the UUID is null or the actor row is missing).
#[derive(Debug, serde::Serialize)]
pub struct AppSettingsWithUsername {
    pub open_signup: bool,
    pub updated_at: Option<String>,
    pub updated_by: Option<uuid::Uuid>,
    pub updated_by_username: Option<String>,
}

/// Load the app settings row (always exists per migration `INSERT`).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_app_settings_load(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<AppSettings, tokio_postgres::Error> {
    let row = client
        .query_one("SELECT open_signup FROM app_settings WHERE id = 1", &[])
        .await?;
    Ok(AppSettings {
        open_signup: row.get(0),
    })
}

/// Load the app settings row joined with the updater's username.
///
/// Mirrors `query_app_settings_load_with_username` in `fuz_app`.
/// `updated_at` is projected as an ISO-8601 UTC string via `to_char` so
/// the wire shape matches the TS reference; `updated_by` is read as a
/// native `uuid::Uuid` column.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_app_settings_load_with_username(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<AppSettingsWithUsername, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns}, act.name AS updated_by_username
         FROM app_settings s
         LEFT JOIN actor act ON act.id = s.updated_by
         WHERE s.id = 1",
        columns = app_settings_columns("s"),
    );
    let row = client.query_one(&sql, &[]).await?;
    Ok(decode_app_settings_with_username_row(&row))
}

/// Update the app settings row.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_app_settings_update(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    settings: AppSettings,
    updated_by: &uuid::Uuid,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE app_settings
             SET open_signup = $1, updated_at = NOW(), updated_by = $2
             WHERE id = 1",
            &[&settings.open_signup, updated_by],
        )
        .await?;
    Ok(())
}
