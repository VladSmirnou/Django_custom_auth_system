from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.contrib.auth.forms import AuthenticationForm
from django.core import mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes


# Some of those tests are not rly neccessary, but i wanna train unittests
class EndpointTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user = get_user_model().objects.create_user(
            username='my_test_user',
            email='my_test_email@gmail.com',
            password='5555aaaa'
        )

    @classmethod
    def tearDownClass(cls):
        pass

    def test_home(self):
        http_requests = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']
        for method in http_requests:
            if method == 'get':
                continue
            response = eval(f'self.client.{method}(reverse(\'home\'))')
            self.assertEqual(response.status_code, 405)

    def test_login_success(self):
        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertTrue(flag)
        
        response = self.client.get(reverse('login'))

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'You are already logged in, logout first if you want to change an account')
        self.assertEqual(len(messages), 1)
        self.assertRedirects(response, '/')
            
    def test_login_fail(self):
        data = {
            'username': 'my_t_email@gmail.com', # email contains an error
            'password': '5555aaaa'
        }

        flag = self.client.login(email=data['username'], password=data['password'])
        self.assertFalse(flag)

        response = self.client.get('/login/')

        form = AuthenticationForm(data=data)

        self.assertFormError(form,
            errors='Please enter a correct email and password. Note that both fields may be case-sensitive.',
            field=None
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'registration/login.html')

    def test_logout_not_auth(self):
        response = self.client.get('/logout/')
        
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'You have to be logged in')
        self.assertEqual(len(messages), 1)
        self.assertRedirects(response, '/')

    def test_logout_sucess(self):
        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertTrue(flag)

        response = self.client.get(reverse('logout'))
        self.assertRedirects(response, '/')

    # def test_sign_up(self):
        # pass

    def test_password_change_not_auth(self):
        response = self.client.get('/password_change/')
        self.assertRedirects(response, '/login/?next=/password_change/')
    
    def test_password_change_fail(self):
        data = {
                'old_password': '5555aaa', #error in the password
                'new_password1': 'mynewpassword',
                'new_password2': 'mynewpass' # two passwords doesn't match
            }

        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertTrue(flag)

        response = self.client.post('/password_change/', data=data)
        
        errors = []
        for field in data:
            if field == 'new_password1':
                continue
            errors.append(response.context['form'].errors[field].get_context()['errors'][0])
        self.assertEqual(
            sorted(errors), [
                'The two password fields didn’t match.',
                'Your old password was entered incorrectly. Please enter it again.'
            ]
        )

    def test_password_change_success(self):
        data = {
                'old_password': '5555aaaa',
                'new_password1': 'mynewpassword123',
                'new_password2': 'mynewpassword123'
            }

        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertTrue(flag)

        user = get_user_model().objects.get(email='my_test_email@gmail.com')
        password_before_request = user.password
        
        response = self.client.post('/password_change/', data=data)
        user.refresh_from_db()
        password_after_request = user.password

        self.assertNotEqual(password_before_request, password_after_request)
        self.assertRedirects(response, '/password_change/done/')

        # login with an old password
        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertFalse(flag)

        # only logged in user can access, not auth must be redirected
        response = self.client.get('/password_change/')
        self.assertRedirects(response, '/login/?next=/password_change/')

        # login with a new password
        flag = self.client.login(email='my_test_email@gmail.com', password='mynewpassword123')
        self.assertTrue(flag)

    def test_password_reset(self):
        response = self.client.post('/password_reset/', data={'email': self.user.email})
        self.assertEqual(len(mail.outbox), 1)

        send_to = vars(mail.outbox[0])['to'][0]
        self.assertEqual(send_to, self.user.email)

        self.assertRedirects(response, '/password_reset/done/')

    def test_password_confirm_uid64_token(self):
        user = get_user_model().objects.get(email=self.user.email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        response = self.client.get(
            path=reverse(
                'password_reset_confirm', kwargs={'uidb64': uid, 'token': token}
            )
        )
        path_info = response.request['PATH_INFO']
        uid_from_email, token_from_email = path_info.removeprefix('/password_reset_confirm/').rstrip('/').split('/')

        decoded_uid_from_email = int(urlsafe_base64_decode(uid_from_email).decode())

        self.assertEqual(decoded_uid_from_email, user.pk)
        self.assertTrue(default_token_generator.check_token(user, token_from_email))
        self.assertRedirects(response, '/password_reset_complete/')

    def test_password_reset_complete_GET(self):
        # user without a token
        response = self.client.get('/password_reset_complete/')
        self.assertEqual(response.status_code, 404)

        # user with an invalid token
        token = 'random_invalid_token'
        user = get_user_model().objects.get(email='my_test_email@gmail.com')
       
        encoded_user = urlsafe_base64_encode(force_bytes(user.pk))
        session = self.client.session
        session['token'] = token
        session['encoded_user'] = encoded_user
        session.save()

        response = self.client.get('/password_reset_complete/')
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'Activation link is invalid. Try again.')
        self.assertRedirects(response, '/')
        
        # user with a valid token
        token = default_token_generator.make_token(user)
        session['token'] = token
        session.save()
        response = self.client.get('/password_reset_complete/')

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'password/password_reset_complete.html')

    def test_password_reset_complete_POST(self):
        # user without a token
        response = self.client.post('/password_reset_complete/')
        self.assertEqual(response.status_code, 404)

        user = get_user_model().objects.get(email='my_test_email@gmail.com')
        data = {
            'user': user.email, # in POST user is represented by a string email value
            'new_password1': 'mynewsuperpassword',
            'new_password2': 'mynewsuperpassword'
        }
        # user with a valid token
        session = self.client.session
        token = default_token_generator.make_token(user)
        encoded_user = urlsafe_base64_encode(force_bytes(user.pk))
        session['token'] = token
        session['encoded_user'] = encoded_user
        session.save()
        response = self.client.post('/password_reset_complete/', data=data)
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'Your password was successfully changed, you\'re now able to log in.')
        self.assertRedirects(response, '/login/')

        # check, if a user can get /logout/ page after changing a password, should be redirected
        # + error message
        response = self.client.get('/logout/')
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'You have to be logged in')
        self.assertRedirects(response, '/')

        # user with an invalid token, shoud be redirected + error message
        session['token'] = 'my_super_token'
        session.save()
        response = self.client.post('/password_reset_complete/', data=data)
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), 'Activation link is invalid. Try again.')
        self.assertRedirects(response, '/')

        # check, if a user can login with an old password
        flag = self.client.login(email='my_test_email@gmail.com', password='5555aaaa')
        self.assertFalse(flag)

        # check, if a user can login with a new password
        flag = self.client.login(email='my_test_email@gmail.com', password='mynewsuperpassword')
        self.assertTrue(flag)
