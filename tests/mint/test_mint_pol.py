import datetime
import hashlib
from types import SimpleNamespace

import httpx
import pytest
import respx
from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.settings import settings
from cashu.mint import app as app_module
from cashu.mint import middleware as middleware_module
from cashu.mint import router as router_module
from cashu.mint.pol import (
    SparseMerkleSumTree,
    submit_to_ots,
    update_pol_manifests,
)
from cashu.wallet.cli.cli import pol as pol_group


def _build_router_app() -> FastAPI:
    app = FastAPI()
    middleware_module.add_middlewares(app)
    app.middleware("http")(app_module.catch_exceptions)
    app.include_router(router_module.router)
    return app

def test_sparse_merkle_sum_tree_computation():
    leaves = {}
    items = ["blinded_msg_1", "blinded_msg_2"]
    values = [100, 250]
    
    for item, val in zip(items, values):
        h = hashlib.sha256(item.encode('utf-8')).digest()
        idx_int = int.from_bytes(h, 'big')
        leaves[idx_int] = (h, val)
        
    tree = SparseMerkleSumTree(leaves)
    root_hash, root_sum = tree.root
    
    assert root_sum == 350
    assert len(root_hash) == 32
    
    h1_hex = hashlib.sha256(items[0].encode('utf-8')).hexdigest()
    idx1_int = int.from_bytes(bytes.fromhex(h1_hex), 'big')
    
    # get_proof now returns (compact_mask, siblings)
    compact_mask, proof1 = tree.get_proof(idx1_int)
    
    # It must be compact (less than 256 items)
    assert len(proof1) < 256
    
    # Reconstruct the 256 siblings list using compact_mask and default_nodes
    mask_int = int(compact_mask, 16)
    sibling_iter = iter(proof1)
    reconstructed_siblings = []
    for d in range(256):
        bit = (mask_int >> d) & 1
        if bit == 1:
            reconstructed_siblings.append(next(sibling_iter))
        else:
            def_hash, def_sum = tree.default_nodes[d]
            reconstructed_siblings.append({
                "hash": def_hash.hex(),
                "sum": def_sum
            })
            
    # Verify mathematically level-by-level using reconstructed siblings
    current_hash = bytes.fromhex(h1_hex)
    current_sum = values[0]
    for d in range(256):
        sib = reconstructed_siblings[d]
        sib_hash = bytes.fromhex(sib["hash"])
        sib_sum = sib["sum"]
        
        bit = (idx1_int >> d) & 1
        parent_sum = current_sum + sib_sum
        
        if bit == 0:
            left_hash = current_hash
            left_sum = current_sum
            right_hash = sib_hash
            right_sum = sib_sum
        else:
            left_hash = sib_hash
            left_sum = sib_sum
            right_hash = current_hash
            right_sum = current_sum
            
        current_hash = hashlib.sha256(
            left_hash + right_hash + 
            left_sum.to_bytes(8, 'big') + right_sum.to_bytes(8, 'big')
        ).digest()
        current_sum = parent_sum
        
    assert current_hash == root_hash
    assert current_sum == root_sum


@respx.mock
@pytest.mark.asyncio
async def test_submit_to_ots_success_and_failover():
    digest = hashlib.sha256(b"hello").digest()
    
    alice_route = respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"ALICE_OTS_RECEIPT")
    )
    bob_route = respx.post("https://bob.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"BOB_OTS_RECEIPT")
    )
    
    res = await submit_to_ots(digest)
    assert res == b"ALICE_OTS_RECEIPT"
    assert alice_route.called
    
    alice_route.reset()
    bob_route.reset()
    
    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(500)
    )
    res = await submit_to_ots(digest)
    assert res == b"BOB_OTS_RECEIPT"
    assert bob_route.called
    
    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(500)
    )
    respx.post("https://bob.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(ConnectionError) as exc_info:
        await submit_to_ots(digest)
    assert "All OTS calendar servers failed" in str(exc_info.value)


@respx.mock
@pytest.mark.asyncio
async def test_update_pol_manifests_lifecycle(monkeypatch):
    keyset_id = "test_lifecycle_keyset"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=True,
        private_keys={},
        final_expiry=None,
    )
    
    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"MOCK_LIFECYCLE_OTS")
    )
    
    epochs_in_db = []
    
    async def mock_fetchall(query, values=None):
        if "promises" in query:
            return [{"amount": 100, "b_": "B_hex_1", "created": datetime.datetime.now(datetime.timezone.utc)}]
        elif "proofs_used" in query:
            return []
        return []
        
    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            if epochs_in_db:
                epoch = epochs_in_db[-1]
                return epoch
            return None
        return None
        
    async def mock_execute(query, values=None):
        if "INSERT INTO" in query and "pol_epochs" in query:
            epochs_in_db.append(values)
            return None
        return None
        
    mock_db = SimpleNamespace(
        fetchall=mock_fetchall,
        fetchone=mock_fetchone,
        execute=mock_execute,
        table_with_schema=lambda t: t
    )
    
    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db
    )
    
    settings.mint_pol_epoch_seconds = 5
    
    # 1. First run: No epoch in DB -> Must publish Epoch 1
    await update_pol_manifests(mock_ledger)
    assert len(epochs_in_db) == 1
    assert epochs_in_db[0]["epoch_index"] == 1
    
    # 2. Second run: Interval not elapsed -> Should skip publishing
    await update_pol_manifests(mock_ledger)
    assert len(epochs_in_db) == 1
    
    # 3. Third run: Set elapsed to more than 5 seconds -> Should publish Epoch 2
    epochs_in_db[0]["timestamp"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
    await update_pol_manifests(mock_ledger)
    assert len(epochs_in_db) == 2
    assert epochs_in_db[1]["epoch_index"] == 2


@respx.mock
def test_pol_endpoints_and_mock_ledger(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )
    
    y1 = hash_to_curve(b"secret_1").format().hex()
    y2 = hash_to_curve(b"secret_2").format().hex()
    
    epoch_timestamp = datetime.datetime.now(datetime.timezone.utc)
    
    async def mock_fetchall(query, values=None):
        if "promises" in query:
            return [
                {"amount": 100, "b_": "B_hex_1", "created": epoch_timestamp},
                {"amount": 200, "b_": "B_hex_2", "created": epoch_timestamp},
            ]
        elif "proofs_used" in query:
            return [
                {"amount": 50, "secret": "secret_1", "y": y1, "created": epoch_timestamp},
                {"amount": 150, "secret": "secret_2", "y": y2, "created": epoch_timestamp},
            ]
        return []
        
    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": epoch_timestamp,
                "root_issued_hash": hashlib.sha256(b"issued").hexdigest(),
                "root_issued_sum": 300,
                "root_spent_hash": hashlib.sha256(b"spent").hexdigest(),
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None
        
    mock_db = SimpleNamespace(
        fetchall=mock_fetchall,
        fetchone=mock_fetchone,
        execute=lambda q, v=None: None,
        table_with_schema=lambda t: t
    )
    
    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db
    )
    
    monkeypatch.setattr(router_module, "ledger", mock_ledger)
    
    respx.post("https://alice.btc.calendar.opentimestamps.org/digest").mock(
        return_value=httpx.Response(200, content=b"ALICE_OTS_RECEIPT")
    )
    
    app = _build_router_app()
    client = TestClient(app)
    
    # Test GET /v1/pol/{keyset_id}/manifest
    resp_manifest = client.get(f"/v1/pol/{keyset_id}/manifest")
    assert resp_manifest.status_code == 200
    manifest_data = resp_manifest.json()
    assert manifest_data["epoch_index"] == 1
    assert manifest_data["outstanding_balance"] == 100
    
    # Test POST /v1/pol/{keyset_id}/proofs/issued
    resp = client.post(
        f"/v1/pol/{keyset_id}/proofs/issued",
        json={"blinded_messages": ["B_hex_1", "B_hex_non_existent"]}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "proofs" in data
    assert len(data["proofs"]) == 2
    
    # Check item 1 (active leaf, value 100)
    item1 = data["proofs"][0]
    assert item1["item"] == "B_hex_1"
    assert item1["value"] == 100
    assert len(item1["siblings"]) < 256  # Sibling proofs must be compact (under 256 items)
    
    # Check item 2 (non-existent, value 0)
    item2 = data["proofs"][1]
    assert item2["item"] == "B_hex_non_existent"
    assert item2["value"] == 0
    assert len(item2["siblings"]) < 256  # Sibling proofs must be compact (under 256 items)

    # Test POST /v1/pol/{keyset_id}/proofs/spent
    resp_spent = client.post(
        f"/v1/pol/{keyset_id}/proofs/spent",
        json={"secrets": ["secret_1", "secret_non_existent"]}
    )
    assert resp_spent.status_code == 200
    spent_data = resp_spent.json()
    assert len(spent_data["proofs"]) == 2
    assert spent_data["proofs"][0]["item"] == "secret_1"
    assert spent_data["proofs"][0]["value"] == 50
    assert spent_data["proofs"][0]["compact_mask"] is not None
    assert spent_data["proofs"][1]["item"] == "secret_non_existent"
    assert spent_data["proofs"][1]["value"] == 0


@respx.mock
def test_pol_audit_challenge_missing_and_invalid_proofs(monkeypatch):
    keyset_id = "test_keyset_pol"
    mock_keyset = SimpleNamespace(
        id=keyset_id,
        active=False,
        private_keys={},
        final_expiry=None,
    )
    
    async def mock_fetchall(query, values=None):
        if "promises" in query:
            return []
        elif "proofs_used" in query:
            return []
        return []
        
    async def mock_fetchone(query, values=None):
        if "pol_epochs" in query:
            # We return a mock epoch with an invalid root hash to trigger verification walk failures
            return {
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc),
                "root_issued_hash": "00" * 32,
                "root_spent_hash": "00" * 32,
                "root_issued_sum": 300,
                "root_spent_sum": 200,
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "signature": "mock_sig",
            }
        return None
        
    async def mock_execute(query, values=None):
        return None
        
    mock_db = SimpleNamespace(
        fetchall=mock_fetchall,
        fetchone=mock_fetchone,
        execute=mock_execute,
        table_with_schema=lambda t: t
    )
    
    mock_ledger = SimpleNamespace(
        keysets={keyset_id: mock_keyset},
        db=mock_db
    )
    
    monkeypatch.setattr(router_module, "ledger", mock_ledger)
    
    # Calculate the exact expected B_ hex derived from our seed and mock private keys
    # to return in the mocked proofs/issued endpoint response
    from coincurve import PrivateKey

    from cashu.core.crypto import b_dhke
    secret_str = b"secret_1".hex()
    r_priv = PrivateKey(b"\x01"*32)
    B_, _ = b_dhke.step1_alice(secret_str, r_priv)
    expected_b_hex = B_.format().hex()

    # Mock all the HTTP requests made during the pol audit CLI command
    respx.get("http://localhost:3337/v1/pol/test_keyset_pol/manifest").mock(
        return_value=httpx.Response(
            200,
            json={
                "keyset_id": keyset_id,
                "epoch_index": 1,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "signing_pubkey": "00"*33,
                "root_issued": {"hash": "00"*32, "sum": 300},
                "root_spent": {"hash": "00"*32, "sum": 200},
                "outstanding_balance": 100,
                "ots_receipt": "010203",
                "mint_signature": "mock_sig"
            }
        )
    )
    
    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/spent").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": "secret_1",
                        "index": "00"*32,
                        "value": 0,
                        "compact_mask": "0x0",
                        "siblings": []
                    }
                ]
            }
        )
    )
    
    respx.post("http://localhost:3337/v1/pol/test_keyset_pol/proofs/issued").mock(
        return_value=httpx.Response(
            200,
            json={
                "proofs": [
                    {
                        "item": expected_b_hex,
                        "index": "00"*32,
                        "value": 100,
                        "compact_mask": "0x0",
                        "siblings": []
                    }
                ]
            }
        )
    )
    
    app = _build_router_app()
    TestClient(app)
    
    # Set up Mock wallet obj_ctx with async mocks
    async def mock_load_proofs(reload=True):
        return None
        
    async def mock_generate_determinstic_secret(counter, keyset_id):
        return (b"secret_1", b"\x01"*32, "HMAC-SHA256:test_keyset_pol:42")
        
    obj_ctx = {
        "HOST": "http://localhost:3337",
        "WALLET_NAME": "test_wallet",
        "WALLET": SimpleNamespace(
            url="http://localhost:3337",
            load_proofs=mock_load_proofs,
            db=mock_db,
            proofs=[
                SimpleNamespace(
                    id=keyset_id,
                    amount=100,
                    secret="secret_1",
                    C="C_hex_1",
                    derivation_path="HMAC-SHA256:test_keyset_pol:42"
                )
            ],
            generate_determinstic_secret=mock_generate_determinstic_secret
        )
    }
    
    # Run the pol audit click subcommand
    runner = CliRunner()
    result = runner.invoke(pol_group, ["audit", keyset_id], obj=obj_ctx)
    
    assert result.exception is None
    # Verify that the CLI detected path verification failures, flagged them, and generated the JSON Cryptographic Challenges
    assert "CRYPTOGRAPHIC FRAUD CHALLENGE" in result.output
    assert "spent_non_inclusion_path" in result.output
    assert "issued_inclusion_path" in result.output
