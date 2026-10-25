"""Tests for CPPMQueries local-user methods (CPPM_*_LOCAL_USER handlers)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock
import pytest

from client import CPPMClient
from queries import CPPMQueries


@pytest.fixture
def mock_client():
    return MagicMock(spec=CPPMClient)


@pytest.fixture
def queries(mock_client):
    return CPPMQueries(mock_client)


def _not_found():
    return {"status": "ERROR", "message": "404", "code": 404}


def test_create_posts_new_user_with_marker(queries, mock_client):
    mock_client._request.side_effect = [_not_found(), {"id": 7}]
    res = queries.create_local_user("jsmith", "pw1", role_name="[Employee]", tenant_slug="lrb")
    assert res == {"status": "SUCCESS", "user_id": "jsmith", "created": True}
    method, path = mock_client._request.call_args_list[1].args
    body = mock_client._request.call_args_list[1].kwargs["json"]
    assert (method, path) == ("POST", "/api/local-user")
    assert body["user_id"] == "jsmith" and body["password"] == "pw1"
    assert body["attributes"]["LM_Managed"] == "dot1x_jit"
    assert body["attributes"]["Tenant_Slug"] == "lrb"


def test_create_refuses_unmanaged_existing(queries, mock_client):
    mock_client._request.side_effect = [{"user_id": "jsmith", "attributes": {}}]
    res = queries.create_local_user("jsmith", "pw1")
    assert res["status"] == "ERROR" and res["code"] == 409
    assert mock_client._request.call_count == 1


def test_create_rekeys_managed_existing(queries, mock_client):
    mock_client._request.side_effect = [
        {"user_id": "jsmith", "password": "x", "attributes": {"LM_Managed": "dot1x_jit"}},
        {"status": "SUCCESS"},
    ]
    res = queries.create_local_user("jsmith", "pw2")
    assert res["created"] is False
    method, path = mock_client._request.call_args_list[1].args
    assert (method, path) == ("PATCH", "/api/local-user/user-id/jsmith")
    assert mock_client._request.call_args_list[1].kwargs["json"]["password"] == "pw2"


def test_get_strips_password(queries, mock_client):
    mock_client._request.return_value = {"user_id": "a", "password": "secret"}
    res = queries.get_local_user("a")
    assert res["found"] and "password" not in res["user"]


def test_set_password_patches(queries, mock_client):
    mock_client._request.return_value = {"status": "SUCCESS"}
    assert queries.set_local_user_password("a b", "pw")["status"] == "SUCCESS"
    assert mock_client._request.call_args.args == ("PATCH", "/api/local-user/user-id/a%20b")


def test_delete_absent_is_success(queries, mock_client):
    mock_client._request.return_value = _not_found()
    res = queries.delete_local_user("gone")
    assert res == {"status": "SUCCESS", "user_id": "gone", "deleted": False}


def test_delete_error_propagates(queries, mock_client):
    mock_client._request.return_value = {"status": "ERROR", "message": "boom", "code": 500}
    assert queries.delete_local_user("x")["status"] == "ERROR"


def test_missing_args(queries, mock_client):
    assert queries.create_local_user("", "pw")["status"] == "ERROR"
    assert queries.set_local_user_password("a", "")["status"] == "ERROR"
    mock_client._request.assert_not_called()
