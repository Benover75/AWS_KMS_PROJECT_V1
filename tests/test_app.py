import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'AWS KMS Web UI' in rv.data

def test_es_logs(client, monkeypatch):
    # Mock Elasticsearch for test
    class MockES:
        def search(self, *args, **kwargs):
            return {'hits': {'hits': [{'_source': {'test': 'ok'}}]}}
    monkeypatch.setattr('app.Elasticsearch', lambda *a, **kw: MockES())
    rv = client.get('/api/es-logs')
    assert rv.status_code == 200
    assert b'test' in rv.data 