from django.shortcuts import render

def login(request):
#Launch ouath to auth backed (dms-oauth)
# http://0.0.0.0/accounts/login/?next=/oauth2/authorize/%3Fclient_id%3D7URDZMmfdUSRjr1GHj6MH4zpXzBClWqQdHrnEwDg%26
# redirect_uri%3Dhttp%3A//
# 127.0.0.1%3A8000/complete/dmsu-oauth2/%26state%3DkYGAa9dbO2kImVOHwsTpkgSkq8Ce8oe0%26response_type%3Dcode
    return render(request, 'main/login.html')
'''
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/oauth.py#L308
https://python-social-auth.readthedocs.io/en/latest/backends/implementation.html#oauth2
'''
from datetime import datetime

from social_core.backends.oauth import BaseOAuth2
from django.conf import settings



class DMSUOAuth2(BaseOAuth2):
    name = 'dmsu-oauth2'
    ID_KEY = 'id'
    AUTHORIZATION_URL = settings.DMSU_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = settings.DMSU_ACCESS_TOKEN_URL
    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False


    def get_user_details(self, response):
        """
        Return user details

        Invoke by social_details pipeline.
        """

        response_binded = {'id': response['id'],
                'username': response['username'],
                'email': response['email'],
                'first_name': response.get('first_name', ''),
                'last_name': response.get('last_name', ''),
                'middle_name': response.get('middle_name', ''),
                'phone_number': response.get('phone_number'),
                'access_token': response.get('access_token'),
                'refresh_token': response.get('refresh_token'),
                'token_type': response.get('token_type'),
                'expires_in': response.get('expires_in'),
                'is_active': response.get('is_active'),
                'inn': response.get('inn', ''),
                }
        try:
            response_binded['date_password_expired'] = datetime.strptime(response.get('date_off_password'), '%Y-%m-%d').date()
        except (ValueError, TypeError):
            ...

        try:
           response_binded['date_joined'] = datetime.strptime(response.get('date_joined'), '%Y-%m-%dT%H:%M:%S')
        except (ValueError, TypeError):
            ...

        return response_binded


    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""

        return self.get_json(
            settings.DMSU_BASE_URL + 'api/hello/',
            headers={'Authorization': 'Bearer {0}'.format(access_token)},
            method='GET'
        )
