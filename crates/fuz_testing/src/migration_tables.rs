//! The tables a migration chain creates, read off its DDL.
//!
//! What a spine crate's table-name const is held to, so a table the chain adds
//! can't be left out of the const (and so out of every `_testing_reset`
//! truncate spliced from it).

use std::collections::BTreeSet;

use fuz_db::MigrationNamespace;

/// The tables `namespace`'s migrations leave behind.
///
/// The chain's statements replay in migration order: each `CREATE TABLE` adds
/// its target, each `ALTER TABLE … RENAME TO` moves one, and each `DROP TABLE`
/// removes every table it lists.
///
/// Reads the DDL as text. `--` and `/* */` comments and `'…'` string literals
/// are skipped; `IF [NOT] EXISTS` is accepted, and a `public.` qualifier or
/// double quotes are stripped. A literal closes at the next `'`, so an
/// escape-string `E'\''` misparses, and `$$` dollar-quoted bodies are not
/// skipped — their words read as DDL. `UNLOGGED` tables count; `TEMP` /
/// `TEMPORARY` ones don't, since they end with the migration's session. A
/// table created some other way (a `CREATE TABLE` built as a string and
/// `EXECUTE`d) is not seen — the crate's live-schema registry
/// (`assert_column_projections`) is the guard for those.
#[must_use]
pub fn migration_created_tables(namespace: &MigrationNamespace) -> BTreeSet<String> {
    let mut tables = BTreeSet::new();
    for migration in namespace.migrations {
        let words = sql_words(migration.sql);
        let word = |i: usize| words.get(i).map_or("", String::as_str);
        let mut i = 0;
        while i < words.len() {
            match word(i) {
                "create" => {
                    let mut j = i + 1;
                    if matches!(word(j), "global" | "local") {
                        j += 1;
                    }
                    let temporary = matches!(word(j), "temp" | "temporary");
                    if temporary || word(j) == "unlogged" {
                        j += 1;
                    }
                    if word(j) == "table" {
                        j = skip_if_exists(&words, j + 1);
                        if !temporary && let Some(name) = words.get(j) {
                            tables.insert(table_name(name));
                        }
                    }
                    i = j + 1;
                }
                "drop" if word(i + 1) == "table" => {
                    let mut j = skip_if_exists(&words, i + 2);
                    while let Some(name) = words.get(j) {
                        tables.remove(&table_name(name));
                        if word(j + 1) != "," {
                            break;
                        }
                        j += 2;
                    }
                    i = j + 1;
                }
                "alter" if word(i + 1) == "table" => {
                    let mut j = skip_if_exists(&words, i + 2);
                    if word(j) == "only" {
                        j += 1;
                    }
                    if word(j + 1) == "rename"
                        && word(j + 2) == "to"
                        && let (Some(from), Some(to)) = (words.get(j), words.get(j + 3))
                        && tables.remove(&table_name(from))
                    {
                        tables.insert(table_name(to));
                    }
                    i = j + 1;
                }
                _ => i += 1,
            }
        }
    }
    tables
}

/// The index past an `IF NOT EXISTS` / `IF EXISTS` at `i`, else `i`.
fn skip_if_exists(words: &[String], mut i: usize) -> usize {
    if words.get(i).is_some_and(|w| w == "if") {
        while words.get(i).is_some_and(|w| w != "exists") {
            i += 1;
        }
        i += 1;
    }
    i
}

/// `sql` lowercased and split into words: `--` and (nesting) `/* */` comments
/// and `'…'` string literals dropped, whitespace, `(`, `)`, and `;` treated as
/// separators, and `,` kept as a word of its own (a `DROP TABLE` list).
fn sql_words(sql: &str) -> Vec<String> {
    fn flush(words: &mut Vec<String>, word: &mut String) {
        if !word.is_empty() {
            words.push(std::mem::take(word).to_lowercase());
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '-' if chars.peek() == Some(&'-') => {
                flush(&mut words, &mut word);
                chars.find(|&c| c == '\n');
            }
            '/' if chars.peek() == Some(&'*') => {
                flush(&mut words, &mut word);
                chars.next();
                let mut depth = 1_usize;
                while depth > 0 {
                    match chars.next() {
                        Some('/') if chars.peek() == Some(&'*') => {
                            chars.next();
                            depth += 1;
                        }
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            depth -= 1;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            // a doubled `''` closes and reopens, so it skips as one literal
            '\'' => {
                flush(&mut words, &mut word);
                chars.find(|&c| c == '\'');
            }
            ',' => {
                flush(&mut words, &mut word);
                words.push(",".to_owned());
            }
            c if c.is_whitespace() || matches!(c, '(' | ')' | ';') => {
                flush(&mut words, &mut word);
            }
            c => word.push(c),
        }
    }
    flush(&mut words, &mut word);
    words
}

fn table_name(word: &str) -> String {
    let unquoted = word.replace('"', "");
    unquoted
        .strip_prefix("public.")
        .unwrap_or(&unquoted)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use fuz_db::Migration;

    use super::*;

    #[test]
    fn reads_creates_less_drops_across_the_chain() {
        const MIGRATIONS: &[Migration] = &[
            Migration {
                name: "first",
                sql: "-- CREATE TABLE commented_out (id int);\n\
                      CREATE TABLE plain (id int);\n\
                      create table if not exists Lower(id int);\n\
                      CREATE TABLE \"public\".\"quoted\" (id int);\n\
                      CREATE TABLE public.qualified (id int);\n\
                      CREATE INDEX plain_idx ON plain (id);",
            },
            Migration {
                name: "second",
                sql: "DROP TABLE IF EXISTS qualified;\nCREATE TABLE later (id int);",
            },
        ];
        let tables = migration_created_tables(&MigrationNamespace::new("shapes", MIGRATIONS));
        assert_eq!(
            tables.into_iter().collect::<Vec<_>>(),
            ["later", "lower", "plain", "quoted"]
        );
    }

    #[test]
    fn reads_drop_lists_block_comments_literals_and_renames() {
        const MIGRATIONS: &[Migration] = &[
            Migration {
                name: "first",
                sql: "CREATE TABLE a (id int); CREATE TABLE b (id int); CREATE TABLE c (id int);\n\
                      /* CREATE TABLE ghost (id int);\n\
                         /* nested */ CREATE TABLE nested_ghost (id int); */\n\
                      CREATE UNLOGGED TABLE IF NOT EXISTS unlogged (id int);\n\
                      CREATE TEMP TABLE temp_scratch (id int);\n\
                      CREATE GLOBAL TEMPORARY TABLE temporary_scratch (id int);\n\
                      INSERT INTO a VALUES ('-- it''s'); CREATE TABLE after_literal (id int);\n\
                      INSERT INTO a VALUES ('CREATE TABLE in_literal (id int)');\n\
                      CREATE TABLE renamed_from (id int);",
            },
            Migration {
                name: "second",
                sql: "DROP TABLE IF EXISTS a, public.b CASCADE;\n\
                      ALTER TABLE IF EXISTS ONLY renamed_from RENAME TO renamed_to;\n\
                      ALTER TABLE c RENAME COLUMN id TO c_id;\n\
                      ALTER TABLE c RENAME id TO c_key;",
            },
        ];
        let tables = migration_created_tables(&MigrationNamespace::new("shapes", MIGRATIONS));
        assert_eq!(
            tables.into_iter().collect::<Vec<_>>(),
            ["after_literal", "c", "renamed_to", "unlogged"]
        );
    }
}
