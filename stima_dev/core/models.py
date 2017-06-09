from django.db import models
from django.contrib.auth.models import User

class manager(models.Model):
    CPF = models.CharField(max_length=11)
    nome = models.CharField(max_length=200)
    usuario = models.OneToOneField(User)
    telefone = models.CharField(max_length=16)

    def __str__(self): # chave primaria que vai ser mostrada no banco de dados das assinaturas
        return self.usuario.username # pra mostrar o cpf do assinante ao inves de 'Assinante object'
