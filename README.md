# SAMBA4-SCRIPT-INSTALADOR-AUTOMATIZADO

```
#########################################################################################
#            _______.     ___      .___  ___. .______        ___     _  _               #
#           /       |    /   \     |   \/   | |   _  \      /   \   | || |              #
#          |   (----`   /  ^  \    |  \  /  | |  |_)  |    /  ^  \  | || |_             #
#           \   \      /  /_\  \   |  |\/|  | |   _  <    /  /_\  \ |__   _|            #
#       .----)   |    /  _____  \  |  |  |  | |  |_)  |  /  _____  \   | |              #
#       |_______/    /__/     \__\ |__|  |__| |______/  /__/     \__\  |_|              #
#                                                                                       #
#########################################################################################

Title:                 : Samba4 4.11.1
Description            : Samba4 Instalador Automatizado - FREE
Facebook               : https://www.facebook.com/YuriBucci
E-mail:                : yuri.bucci@outlook.com
Date                   : 22/10/2019
Version                : 6.0

#########################################################################################
#                                                                                       #
#     * SCRIPT COMPLETO COM DC E FS ADICIONAIS, COM REPLICAÇÃO DO SYSVOL EM CLUSTER ?   #
#     * AULAS PERSONALIZADAS SOBRE SAMBA4 ?                                             #
#     * SUPORTE EM SAMBA4 ?                                                             #
#     * PERSONALIZAÇÃO EXCLUSIVA DO SCRIPT ?                                            #
#                                                                                       #
#                ENTRE EM CONTATO PELO E-MAIL yuri.bucci@outlook.com                    #
#                                                                                       #
#########################################################################################

DICAS DE USO:

- CRIACAO DE PASTAS

* CRIE NOVAS PASTAS UTILIZANDO O COMANDO 'mkdir folder/'
* SEMPRE ALTERE AS PERMISSÕES COM O COMANDO 'chown root.'Domain Admins' folder/ -R' (ASPAS DUPLAS EM DOMAIN ADMINS)

- BACKUP

* UTILIZE O VEEAMBACKUP ATRAVES DO COMANDO 'veeamconfig ui'
* SEMPRE UTILIZE O BACKUP A NIVEL DE PARTICAO E/OU LVM PARA QUE AS PERMISSOES EXTENDIDAS FUNCIONEM
* ADICIONE OS SCRIPTS NA CRIAÇÃO DO BACKUP: /etc/veeam/scripts/pre.sh (REALIZA O BACKUP DO SAMBA4) E /etc/veeam/scripts/email.sh (ENVIA O E-MAIL)

- COMANDOS UTEIS
* samba-tool ntacl sysvolreset (SOMENTE FUNCIONA COM A RETIRADA DO ITEM full_audit DO /etc/samba/smb.conf) - RESETA AS PERMISSÕES DAS PASTAS SYSVOL E GPOS
* samba-tool dbcheck --cross-ncs --fix --yes (VERIFICA O BANCO DE DADOS DO SAMBA E REPARA O MESMO)
* samba-tool dbcheck --reindex (REINDEXA O BANCO DE DADOS)
* samba_dnsupdate --all-names --verbose (ATUALIZA O DNS BIND)

- ADMINISTRACAO DO DOMINIO

* ADICIONE UMA MAQUINA WINDOWS NO DOMINIO E INSTALE O RSAT PARA ADMINISTRACAO DO SEU DOMINIO
* CONFIGURE O DNS REVERSO
* DESABILITE A EXPIRACAO DE SENHA DO ADMINISTRATOR

```

