from django.test import TestCase
from .models import Post
from django.contrib.auth.models import User

class PostModelTest(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='testuser', password='12345')
        self.post = Post.objects.create(author=user, title='Test Post', body='This is a test post.')

    def test_post_creation(self):
        self.assertEqual(self.post.title, 'Test Post')
        self.assertEqual(self.post.body, 'This is a test post.')
        self.assertEqual(self.post.author.username, 'testuser')

    def test_post_string_representation(self):
        self.assertEqual(str(self.post), 'Test Post')

# Create your tests here.
