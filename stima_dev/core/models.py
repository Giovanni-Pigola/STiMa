from django.db import models
from django.contrib.auth.models import User

class manager(models.Model):
    CPF = models.CharField(max_length=11)
    nome = models.CharField(max_length=200)
    usuario = models.OneToOneField(User)
    telefone = models.CharField(max_length=16)

    def __str__(self): # chave primaria que vai ser mostrada no banco de dados das assinaturas
        return self.usuario.username # pra mostrar o cpf do assinante ao inves de 'Assinante object'

    ### get_absolute_URl    ## Slug etc

#
# Token Authentication
# Creates new tokes for newly added users
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


# RUN THESE COMANDS IN PYTHON SHELL TO CREATE TOKENS FOR ALL USERS
# from django.contrib.auth.models import User
# from rest_framework.authtoken.models import Token
#
# users = User.objects.all()
# for user in users:
#     token, created = Token.objects.get_or_create(user=user)
#     print (user.username, token.key)