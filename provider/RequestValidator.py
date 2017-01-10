from oauthlib.oauth2 import RequestValidator


class MyRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request):
        try:
            Client.objects.get(client_id=client_id)
            return True
        except Client.DoesNotExist:
            return False