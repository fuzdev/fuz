//! PG-backed integration tests for `PgFactStore` + the fact queries.
//!
//! `--ignored`-gated (needs Postgres). Run:
//! `cargo test -p fuz_fact -- --ignored --test-threads=1`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::path::{Path, PathBuf};

use common::{fresh_db_pool, held_put, insert_cell_ref, system_put};
use fuz_crypto::ContentHash;
use fuz_fact::{
    FactContent, FactError, FactStore, PgFactStore, PutOptions, fact_disk_path, mint_fact_file_url,
    query_orphan_facts_list, query_orphan_facts_select_for_delete, write_fact_atomic,
};

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn put_embedded_then_get_round_trips() {
    let pool = fresh_db_pool().await;
    let store = PgFactStore::new(pool);
    let data = b"hello fact";

    let hash = store
        .put(
            data,
            PutOptions {
                content_type: Some("text/plain".to_owned()),
                refs: None,
                holder: None,
            },
        )
        .await
        .expect("put");
    assert_eq!(hash, ContentHash::blake3(data));
    assert!(store.has(&hash).await.unwrap());
    assert_eq!(store.get(&hash).await.unwrap().as_deref(), Some(&data[..]));

    let meta = store.get_meta(&hash).await.unwrap().expect("meta");
    assert_eq!(meta.size, i64::try_from(data.len()).unwrap());
    assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
    assert!(!meta.external);

    // Idempotent re-put → same hash, no error.
    let again = store.put(data, system_put()).await.unwrap();
    assert_eq!(again, hash);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn put_oversize_spills_to_disk_and_serves() {
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let store = PgFactStore::new(pool)
        .with_disk_root(facts_dir.path().to_path_buf())
        .with_threshold(8);
    let data = b"this body exceeds the eight byte embedded threshold";

    let hash = store.put(data, system_put()).await.expect("put");

    // get fetches + verifies from disk.
    assert_eq!(store.get(&hash).await.unwrap().as_deref(), Some(&data[..]));

    // open returns a streamable disk path (bounded-memory serving).
    match store.open(&hash).await.unwrap().expect("open") {
        FactContent::Disk { path, size } => {
            assert_eq!(size, i64::try_from(data.len()).unwrap());
            assert!(path.exists());
        }
        FactContent::Embedded(_) => panic!("oversize body should be disk-backed"),
    }

    let meta = store.get_meta(&hash).await.unwrap().unwrap();
    assert!(meta.external);

    // delete returns {size, external_url}; second delete is idempotent None.
    let deleted = store.delete(&hash).await.unwrap().expect("deleted row");
    assert_eq!(deleted.size, i64::try_from(data.len()).unwrap());
    assert!(deleted.external_url.is_some());
    assert!(store.delete(&hash).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn explicit_refs_are_recorded() {
    let pool = fresh_db_pool().await;
    let store = PgFactStore::new(pool);
    let target = store.put(b"target", system_put()).await.unwrap();
    let source = store
        .put(
            b"source",
            PutOptions {
                content_type: None,
                refs: Some(vec![target.clone()]),
                holder: None,
            },
        )
        .await
        .unwrap();
    let refs = store.get_refs(&source).await.unwrap();
    assert_eq!(refs, vec![target.to_prefixed()]);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn content_naming_a_hash_records_no_refs() {
    // JSON-typed content whose body names another stored fact's address:
    // with no declared `refs`, no edge is written — the store never scans
    // content, whatever its type
    let pool = fresh_db_pool().await;
    let store = PgFactStore::new(pool);
    let json_put = || PutOptions {
        content_type: Some("application/json".to_owned()),
        refs: None,
        holder: None,
    };
    let target = store.put(b"target", system_put()).await.unwrap();
    let body = format!(r#"{{"hash":"{}"}}"#, target.to_prefixed());
    let source = store.put(body.as_bytes(), json_put()).await.unwrap();
    assert!(store.get_refs(&source).await.unwrap().is_empty());

    let streamed = format!(r#"{{"see":["{}"]}}"#, target.to_prefixed());
    let outcome = store
        .put_stream(Box::pin(streamed.as_bytes()), streamed.len(), json_put())
        .await
        .unwrap();
    assert!(store.get_refs(&outcome.hash).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn orphan_predicate_tracks_cell_refs() {
    let pool = fresh_db_pool().await;
    let store = PgFactStore::new(pool.clone());
    let a = store.put(b"fact A", system_put()).await.unwrap();

    // No cell references A → orphan.
    let listed = query_orphan_facts_list(&pool.get().await.unwrap(), None, 20)
        .await
        .unwrap();
    assert_eq!(listed.count, 1);

    // An active cell referencing A → A is no longer orphan.
    insert_cell_ref(&pool, &a.to_prefixed(), false).await;
    let listed = query_orphan_facts_list(&pool.get().await.unwrap(), None, 20)
        .await
        .unwrap();
    assert_eq!(listed.count, 0);

    // B is referenced ONLY by a soft-deleted cell — which does NOT keep it
    // alive — so B is orphan and A (active ref) is not. select-for-delete
    // under a far-future cutoff returns B only.
    let b = store.put(b"fact B", system_put()).await.unwrap();
    insert_cell_ref(&pool, &b.to_prefixed(), true).await;
    let candidates =
        query_orphan_facts_select_for_delete(&pool.get().await.unwrap(), "2999-01-01T00:00:00Z")
            .await
            .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].hash, b.to_prefixed());
}

/// Backdate every `fact` and `fact_holder` row two days, so each reads as
/// past a one-hour grace cutoff.
async fn age_fact_rows(pool: &fuz_db::Pool) {
    let client = pool.get().await.unwrap();
    for table in ["fact", "fact_holder"] {
        client
            .execute(
                &format!("UPDATE {table} SET created_at = NOW() - INTERVAL '2 days'"),
                &[],
            )
            .await
            .unwrap();
    }
}

/// The orphan hashes past a one-hour cutoff, through both the preview and
/// the select-for-delete query (asserted to agree), sorted.
async fn orphans_past_an_hour(pool: &fuz_db::Pool) -> Vec<String> {
    let client = pool.get().await.unwrap();
    let cutoff: String = client
        .query_one("SELECT (NOW() - INTERVAL '1 hour')::text", &[])
        .await
        .unwrap()
        .get(0);
    let preview = query_orphan_facts_list(&client, Some(&cutoff), 20)
        .await
        .unwrap();
    let mut listed: Vec<String> = preview.sample.into_iter().map(|s| s.hash).collect();
    let mut selected: Vec<String> = query_orphan_facts_select_for_delete(&client, &cutoff)
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.hash)
        .collect();
    listed.sort();
    selected.sort();
    assert_eq!(listed, selected, "the preview and the sweep disagree");
    assert_eq!(
        preview.count,
        i64::try_from(selected.len()).unwrap(),
        "the preview count and the sweep disagree"
    );
    selected
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn orphan_cutoff_keeps_a_fact_put_within_the_window() {
    // A dedup put adds no `fact` row, so `fact.created_at` stays old; the
    // holder row's `created_at` is what marks the fact as recently put.
    let pool = fresh_db_pool().await;
    let (_, alice) = fuz_testing::seed_account_actor(&pool, "alice").await;
    let (_, bob) = fuz_testing::seed_account_actor(&pool, "bob").await;
    let store = PgFactStore::new(pool.clone());
    let reuploaded = store.put(b"re-uploaded", held_put(alice)).await.unwrap();
    let repeated = store.put(b"repeated", held_put(alice)).await.unwrap();
    let stale = store.put(b"stale", held_put(alice)).await.unwrap();
    let seeded = store.put(b"seeded", system_put()).await.unwrap();
    age_fact_rows(&pool).await;

    // Every row is old: all four are past the cutoff.
    let mut all = vec![
        reuploaded.to_prefixed(),
        repeated.to_prefixed(),
        stale.to_prefixed(),
        seeded.to_prefixed(),
    ];
    all.sort();
    assert_eq!(orphans_past_an_hour(&pool).await, all);

    // A second actor re-uploads one (a dedup hit, a fresh holder row), and the
    // first actor repeats its own put of another (refreshing its row).
    store.put(b"re-uploaded", held_put(bob)).await.unwrap();
    store.put(b"repeated", held_put(alice)).await.unwrap();

    // Both are kept; the old orphan whose holders are all old, and the old
    // system-put orphan, are still swept.
    let mut swept = vec![stale.to_prefixed(), seeded.to_prefixed()];
    swept.sort();
    assert_eq!(orphans_past_an_hour(&pool).await, swept);

    // The cutoff is the whole grace filter: the unfiltered preview counts all.
    let client = pool.get().await.unwrap();
    assert_eq!(
        query_orphan_facts_list(&client, None, 20)
            .await
            .unwrap()
            .count,
        4
    );
}

// -- get on a disk-backed row --
//
// `PgFactStore::get` reads a disk-backed fact's bytes from the facts dir, then
// **re-hashes them and compares to the stored `ContentHash`**. A mismatch is the
// store's integrity guard against a CAS file whose bytes drifted (or were
// tampered) out from under the address — it logs and returns `Ok(None)` (treat
// as unavailable), never the wrong bytes. A row whose bytes cannot be read at
// all gets the same `Ok(None)`, not an error: the file is gone, the path is not
// a readable file, the `external_url` is not `file:<shard>/<rest>`, or the
// store has no facts dir. Each test reads the fact back successfully first (or
// beside the refused read), so the `None` is the case under test and not a
// missing row or an empty disk.

/// The embedded threshold the disk-backed tests run at — small enough that
/// [`DISK_BODY`] spills.
const DISK_THRESHOLD: usize = 8;

/// A body over [`DISK_THRESHOLD`].
const DISK_BODY: &[u8] = b"the canonical bytes this address commits to";

/// A store whose bodies over [`DISK_THRESHOLD`] land in the disk CAS under
/// `facts_dir`.
fn disk_store(pool: fuz_db::Pool, facts_dir: &Path) -> PgFactStore {
    PgFactStore::new(pool)
        .with_disk_root(facts_dir.to_path_buf())
        .with_threshold(DISK_THRESHOLD)
}

/// Where the disk CAS keeps `hash` under `facts_dir`.
fn cas_path(facts_dir: &Path, hash: &ContentHash) -> PathBuf {
    let (shard, rest) = fact_disk_path(hash).expect("blake3 hash");
    facts_dir.join(shard).join(rest)
}

/// Seed a `fact` row addressed by `hash` whose bytes live off-row at
/// `external_url` (no embedded bytes), so `get` takes the disk read + verify
/// path. Writes the URL as given, which the store's own writers never do for
/// anything but `file:<shard>/<rest>`.
async fn seed_external_row(pool: &fuz_db::Pool, hash: &ContentHash, external_url: &str, size: i64) {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO fact (hash, external_url, content_type, size) VALUES ($1, $2, $3, $4)",
            &[&hash.to_prefixed(), &external_url, &"text/plain", &size],
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn get_external_verify_mismatch_is_none() {
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let store = disk_store(pool, facts_dir.path());
    let hash = store.put(DISK_BODY, system_put()).await.unwrap();
    let path = cas_path(facts_dir.path(), &hash);

    // Positive control: the bytes on disk re-hash to the address and are served.
    assert_eq!(store.get(&hash).await.unwrap().as_deref(), Some(DISK_BODY));

    // The CAS file now holds different bytes of the same length under the same
    // address — re-hashing fails the equality check and `get` masks them as
    // not-found rather than serving the wrong bytes.
    let mut tampered = DISK_BODY.to_vec();
    tampered[0] ^= 0xff;
    std::fs::write(&path, &tampered).unwrap();
    assert_eq!(store.get(&hash).await.unwrap(), None);
    // The row is still there: the `None` is the verify, not a vanished fact.
    assert!(store.has(&hash).await.unwrap());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn get_external_missing_file_is_none() {
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let store = disk_store(pool, facts_dir.path());
    // Written through the streaming door, which spills to the same CAS.
    let outcome = store
        .put_stream(Box::pin(DISK_BODY), DISK_BODY.len(), system_put())
        .await
        .unwrap();
    let hash = outcome.hash;
    assert_eq!(hash, ContentHash::blake3(DISK_BODY));
    let path = cas_path(facts_dir.path(), &hash);
    assert_eq!(store.get(&hash).await.unwrap().as_deref(), Some(DISK_BODY));

    std::fs::remove_file(&path).unwrap();
    assert_eq!(store.get(&hash).await.unwrap(), None);
    assert!(store.has(&hash).await.unwrap());
    // `open` resolves the path without touching the file.
    assert!(matches!(
        store.open(&hash).await.unwrap(),
        Some(FactContent::Disk { path: p, .. }) if p == path
    ));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn get_external_unreadable_file_is_none() {
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let store = disk_store(pool, facts_dir.path());
    let hash = store.put(DISK_BODY, system_put()).await.unwrap();
    let path = cas_path(facts_dir.path(), &hash);
    assert_eq!(store.get(&hash).await.unwrap().as_deref(), Some(DISK_BODY));

    // A directory where the CAS file was: the path exists, so this is an I/O
    // error on the read and not the missing-file case.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(store.get(&hash).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn get_external_non_file_url_is_none() {
    // Two rows over the same facts dir, each with its bytes sitting at the
    // canonical `<shard>/<rest>` path. One row names them by the canonical
    // `file:` URL; the other by the same `<shard>/<rest>` under another scheme.
    // Only the scheme differs, so a reader that resolved the second row would
    // find intact bytes that verify.
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let dir = facts_dir.path();
    let size = i64::try_from(DISK_BODY.len()).unwrap();

    let canonical_hash = ContentHash::blake3(DISK_BODY);
    let canonical_url = write_fact_atomic(dir, &canonical_hash, DISK_BODY)
        .await
        .unwrap();
    seed_external_row(&pool, &canonical_hash, &canonical_url, size).await;

    let other_body: &[u8] = b"bytes a row names under some other scheme";
    let other_hash = ContentHash::blake3(other_body);
    let other_file_url = write_fact_atomic(dir, &other_hash, other_body)
        .await
        .unwrap();
    let other_url = other_file_url.replacen("file:", "s3:", 1);
    assert_ne!(other_url, other_file_url);
    seed_external_row(
        &pool,
        &other_hash,
        &other_url,
        i64::try_from(other_body.len()).unwrap(),
    )
    .await;
    assert!(cas_path(dir, &other_hash).is_file());

    let store = disk_store(pool, dir);
    // The seeded canonical row reads: the fixture serves.
    assert_eq!(
        store.get(&canonical_hash).await.unwrap().as_deref(),
        Some(DISK_BODY)
    );
    assert!(matches!(
        store.open(&canonical_hash).await.unwrap(),
        Some(FactContent::Disk { .. })
    ));

    // The non-`file:` row is not read.
    assert_eq!(store.get(&other_hash).await.unwrap(), None);
    assert!(store.open(&other_hash).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn external_url_naming_another_facts_file_is_not_read() {
    // A row for one hash whose `external_url` is another stored fact's
    // canonical `file:` URL. The shape is valid and the file is intact, so only
    // the hash-to-path binding refuses it: `open` streams without re-hashing,
    // and would otherwise hand out the other fact's bytes under this address.
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let dir = facts_dir.path();
    let store = disk_store(pool.clone(), dir);
    let other_hash = store.put(DISK_BODY, system_put()).await.unwrap();
    let other_url = mint_fact_file_url(&other_hash).unwrap();
    assert!(cas_path(dir, &other_hash).is_file());

    let hash = ContentHash::blake3(b"bytes this row claims to address");
    seed_external_row(&pool, &hash, &other_url, 1).await;

    // positive control: the other fact itself reads through both doors
    assert_eq!(
        store.get(&other_hash).await.unwrap().as_deref(),
        Some(DISK_BODY)
    );
    assert!(matches!(
        store.open(&other_hash).await.unwrap(),
        Some(FactContent::Disk { .. })
    ));
    assert_eq!(store.get(&hash).await.unwrap(), None);
    assert!(store.open(&hash).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn get_external_without_facts_dir_is_none() {
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let writer = disk_store(pool.clone(), facts_dir.path());
    let hash = writer.put(DISK_BODY, system_put()).await.unwrap();
    assert_eq!(writer.get(&hash).await.unwrap().as_deref(), Some(DISK_BODY));

    // The same row through a store with no facts dir: it sees a disk-backed
    // fact it has no way to read.
    let store = PgFactStore::new(pool);
    assert!(store.get_meta(&hash).await.unwrap().expect("meta").external);
    assert_eq!(store.get(&hash).await.unwrap(), None);
    assert!(matches!(
        store.open(&hash).await,
        Err(FactError::Internal(_))
    ));
}

// -- holders --
//
// Every put that names a holder records `(actor, hash)` in `fact_holder` — a
// fresh insert and a dedup hit alike — and the rows go with their actor or
// fact. (The admission read is `fuz_cell_actions`'s, tested there.)

/// An empty hash list, for `assert_eq!` against one.
const NONE_HELD: [String; 0] = [];

/// The hashes `actor` holds, sorted.
async fn held_by(pool: &fuz_db::Pool, actor: uuid::Uuid) -> Vec<String> {
    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT hash FROM fact_holder WHERE actor_id = $1 ORDER BY hash",
            &[&actor],
        )
        .await
        .unwrap();
    rows.iter().map(|r| r.get(0)).collect()
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn put_records_the_holder_on_insert_and_on_a_dedup_hit() {
    let pool = fresh_db_pool().await;
    let (_, first) = fuz_testing::seed_account_actor(&pool, "first").await;
    let (_, second) = fuz_testing::seed_account_actor(&pool, "second").await;
    let facts_dir = tempfile::tempdir().unwrap();
    let store = disk_store(pool.clone(), facts_dir.path());

    // A system put records nobody.
    let system = store.put(b"seeded", system_put()).await.unwrap();
    assert_eq!(held_by(&pool, first).await, NONE_HELD);

    // The first actor's put of new bytes makes it a holder.
    let hash = store.put(b"shared bytes", held_put(first)).await.unwrap();
    assert_eq!(held_by(&pool, first).await, vec![hash.to_prefixed()]);
    assert_eq!(held_by(&pool, second).await, NONE_HELD);

    // The second actor brings identical bytes: the fact row dedups, and the
    // second actor becomes a holder too.
    let again = store.put(b"shared bytes", held_put(second)).await.unwrap();
    assert_eq!(again, hash);
    assert_eq!(held_by(&pool, second).await, vec![hash.to_prefixed()]);

    // A repeat put by a holder is idempotent.
    store.put(b"shared bytes", held_put(first)).await.unwrap();
    assert_eq!(held_by(&pool, first).await, vec![hash.to_prefixed()]);

    // The streaming door records the holder too, through a disk spill and
    // through a dedup of the system-put fact.
    let streamed = store
        .put_stream(Box::pin(DISK_BODY), DISK_BODY.len(), held_put(second))
        .await
        .unwrap();
    store
        .put_stream(Box::pin(&b"seeded"[..]), 6, held_put(second))
        .await
        .unwrap();
    let mut expected = vec![
        hash.to_prefixed(),
        streamed.hash.to_prefixed(),
        system.to_prefixed(),
    ];
    expected.sort();
    assert_eq!(held_by(&pool, second).await, expected);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn holder_rows_cascade_with_the_actor_and_the_fact() {
    let pool = fresh_db_pool().await;
    let (account, actor) = fuz_testing::seed_account_actor(&pool, "leaver").await;
    let (_, keeper) = fuz_testing::seed_account_actor(&pool, "keeper").await;
    let store = PgFactStore::new(pool.clone());
    let kept = store.put(b"kept", held_put(actor)).await.unwrap();
    store.put(b"kept", held_put(keeper)).await.unwrap();
    let dropped = store.put(b"dropped", held_put(keeper)).await.unwrap();

    // Deleting the account deletes its actor, and the actor's possession with it.
    let client = pool.get().await.unwrap();
    client
        .execute("DELETE FROM account WHERE id = $1", &[&account])
        .await
        .unwrap();
    assert_eq!(held_by(&pool, actor).await, NONE_HELD);
    assert!(store.has(&kept).await.unwrap(), "the fact itself stays");

    // Deleting a fact drops its holder rows.
    store.delete(&dropped).await.unwrap().expect("deleted");
    assert_eq!(held_by(&pool, keeper).await, vec![kept.to_prefixed()]);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_FACT_TEST_URL)"]
async fn concurrent_puts_of_new_bytes_record_every_holder() {
    // Racing first puts of identical bytes: one inserts the fact, the others
    // dedup on its key — every actor ends up a holder, and no put fails.
    let pool = fresh_db_pool().await;
    let mut actors = Vec::new();
    for i in 0..8 {
        actors.push(
            fuz_testing::seed_account_actor(&pool, &format!("racer{i}"))
                .await
                .1,
        );
    }
    let facts_dir = tempfile::tempdir().unwrap();
    for round in 0..5u8 {
        let body = format!("raced bytes {round} {}", "x".repeat(64)).into_bytes();
        let puts = actors.iter().map(|&actor| {
            let store = disk_store(pool.clone(), facts_dir.path()).with_threshold(16);
            let body = body.clone();
            tokio::spawn(async move { store.put(&body, held_put(actor)).await })
        });
        let hashes: Vec<_> = futures::future::join_all(puts)
            .await
            .into_iter()
            .map(|r| r.unwrap().expect("put"))
            .collect();
        assert!(hashes.windows(2).all(|w| w[0] == w[1]));
        for &actor in &actors {
            assert!(
                held_by(&pool, actor)
                    .await
                    .contains(&hashes[0].to_prefixed())
            );
        }
    }
}
