from sqlalchemy import text

from app.audit import GENESIS_HASH, append_entry, verify_chain


def test_single_entry_chains_from_genesis(db, tenant_id):
    append_entry(db, actor="alice@example.com", tenant_id=tenant_id, action="login", target=None, outcome="success")
    result = verify_chain(db)
    assert result.valid
    assert result.total_rows == 1


def test_multiple_entries_chain_correctly(db, tenant_id):
    for i in range(10):
        append_entry(db, actor=f"user{i}@example.com", tenant_id=tenant_id, action="login", target=None, outcome="success")
    result = verify_chain(db)
    assert result.valid
    assert result.total_rows == 10


def test_tampering_with_a_row_content_is_caught(db, tenant_id):
    for i in range(5):
        append_entry(db, actor=f"user{i}@example.com", tenant_id=tenant_id, action="login", target=None, outcome="success")

    # Tamper with row 3's actor field directly - bypassing the ORM/app
    # layer entirely, same as a superuser editing the table by hand.
    db.execute(text("UPDATE audit_log SET actor = 'tampered-actor' WHERE id = 3"))
    db.commit()

    result = verify_chain(db)
    assert not result.valid
    assert result.first_broken_row_id == 3


def test_tampering_with_a_hash_directly_is_caught(db, tenant_id):
    for i in range(5):
        append_entry(db, actor=f"user{i}@example.com", tenant_id=tenant_id, action="login", target=None, outcome="success")

    db.execute(text("UPDATE audit_log SET row_hash = 'deadbeef' WHERE id = 2"))
    db.commit()

    result = verify_chain(db)
    assert not result.valid
    # Row 2's own hash is now wrong AND row 3's prev_hash no longer
    # matches it - either detection is correct, but it must be caught at
    # row 2 or 3, not go unnoticed.
    assert result.first_broken_row_id in (2, 3)


def test_empty_chain_is_valid(db, tenant_id):
    result = verify_chain(db)
    assert result.valid
    assert result.total_rows == 0


def test_genesis_hash_is_used_for_the_first_row(db, tenant_id):
    append_entry(db, actor="first@example.com", tenant_id=tenant_id, action="login", target=None, outcome="success")
    row = db.execute(text("SELECT prev_hash FROM audit_log ORDER BY id LIMIT 1")).mappings().first()
    assert row["prev_hash"] == GENESIS_HASH


def test_append_works_under_the_restricted_app_role(lab_env, tenant_id, db):
    """Regression test for a real bug found building this: SELECT ... FOR
    UPDATE requires UPDATE privilege on the table in Postgres, even just
    to take the row lock - using it to serialize concurrent appends would
    have meant granting shadowtracer_app UPDATE on audit_log, defeating
    the whole point of the append-only grant. append_entry uses a Postgres
    advisory lock instead, which needs no table privilege. This test
    connects as the actual restricted role, not the table owner the `db`
    fixture otherwise uses, so it fails loudly if that regresses."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    restricted_url = (
        f"postgresql+psycopg2://shadowtracer_app:{lab_env['APP_DB_PASSWORD']}"
        f"@127.0.0.1:5432/{lab_env['POSTGRES_DB']}"
    )
    engine = create_engine(restricted_url)
    Session = sessionmaker(bind=engine)
    restricted_db = Session()
    try:
        append_entry(restricted_db, actor="restricted-role-test", tenant_id=tenant_id, action="login", target=None, outcome="success")
    finally:
        restricted_db.close()

    result = verify_chain(db)
    assert result.valid
    assert result.total_rows == 1
