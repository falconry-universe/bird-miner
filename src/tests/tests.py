import json
import pytest
import requests


@pytest.fixture
def valid_handle():
    return "therealxoho"


@pytest.fixture
def base_url():
    return "http://localhost:8080"


def test_handles_no_data(base_url):
    response = requests.post(f"{base_url}/handles", json={})
    assert response.status_code == 400
    data = response.json()
    assert data
    assert data.get("error") == "invalid json"
    assert data.get("status") == "error"


def test_handles_none(base_url, valid_handle):
    response = requests.post(f"{base_url}/handles", json={"handle": None, "platform": None})
    assert response.status_code == 400
    data = response.json()
    assert data
    assert data.get("error") == "handle and platform required"
    assert data.get("status") == "error"


def test_handles_invalid_platform(base_url, valid_handle):
    response = requests.post(f"{base_url}/handles", json={"handle": valid_handle, "platform": "invalid"})
    assert response.status_code == 400
    data = response.json()
    assert data
    assert data.get("error") == "invalid platform"
    assert data.get("status") == "error"


def test_handles_invalid_handle(base_url):
    response = requests.post(f"{base_url}/handles", json={"handle": "invalid", "platform": "twitter"})
    assert response.status_code == 400
    data = response.json()
    assert data
    assert data.get("error") == "invalid handle"
    assert data.get("status") == "error"


def test_handles_valid_handle_and_platform(base_url, valid_handle):
    response = requests.post(f"{base_url}/handles", json={"handle": valid_handle, "platform": "twitter"})
    assert response.status_code == 200
    data = response.json()
    assert data
    data = data.get("twitter")
    assert data
    assert valid_handle not in [x.get("username") for x in data if x]
