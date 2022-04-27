from rest_framework.authtoken.models import Token


def validate_token_and_get_user(token):
    try:
        token_obj = Token.objects.get(key=token)
        user_id = token_obj.user.id
        return {"success": True, "data": {"user_id": user_id}}

    except Token.DoesNotExist:
        return {"success": False, "data": None}
