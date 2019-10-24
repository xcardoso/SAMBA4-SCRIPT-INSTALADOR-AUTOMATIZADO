#!/bin/bash
clear
tee /tmp/arte << \EOF >> /dev/null
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

EOF


######################### VARIAVEIS #####################################
ARTE="cat /tmp/arte"
USUARIO="whoami"
#########################################################################
$ARTE

x="list"
menu ()
{
while true $x != "list"
do
echo "================================================"
echo ""
echo "1) Samba4 PDC (SERVIDOR PRIMARIO)"
echo ""
echo "2) Samba4 DC (PRIMEIRO SERVIDOR ADICIONAL)"
echo ""
echo "3) Samba4 DC (SEGUNDO OU + SERVIDORES ADICIONAIS)"
echo ""
echo "4) Samba4 RODC (PRIMEIRO SERVIDOR ADICIONAL)"
echo ""
echo "5) Samba4 RODC (SEGUNDO OU + SERVIDORES ADICIONAIS)"
echo ""
echo "6) Samba4 FILESERVER (DOMAIN MEMBER)"
echo ""
echo "================================================"

echo "Digite a opção desejada:"
read x
echo "Opção informada ($x)"
echo "================================================"

case "$x" in

    1)
clear
$ARTE
echo "ATENÇÃO EXECUTE ESSE SCRIPT DENTRO DE /USR/LOCAL/SRC!!! E COM SELINUX EM MODO ENFORCING"
sleep 5s
clear
$ARTE
echo -e "VERIFICANDO USUÁRIO LOGADO..."
sleep 2s
clear
$ARTE
if [ "$(whoami)" == "root" ]
then
read -r -p  "USUÁRIO ROOT IDENTIFICADO, DESEJA CONTINUAR A INSTALAÇÃO <ENTER> ou <CTRL+C)? "
else
echo -e "USUÁRIO NÃO É ROOT, POR FAVOR LOGUE COM O USUÁRIO ROOT"
echo -e "PRESSIONE <ENTER> PÁRA FINALIZAR O SCRIPT"
fi
clear
$ARTE
echo -e "VAMOS EXECUTAR ALGUNS AJUSTES ANTES DE INICIAR..."
setenforce 0
systemctl stop libvirtd.service
systemctl disable libvirtd.service
setenforce 0
sleep 3s
clear
$ARTE
echo -e "PREENCHA AS INFORMAÇÕES PEDIDAS...."
sleep 5s
clear
$ARTE
echo -e "Exemplos:
Hostname Realm: servidor-pdc.contoso.local
Nome do Servidor: servidor-pdc
Dominio Realm: contoso.local
Dominio NETBIOS: contoso
Nome da OU Raiz: CONTOSO
Endereço IP do Servidor: 192.168.0.10
Range de rede: 192.168.0.0/24
Interface de rede: ens192
Senha do Administrator: ******* (Digitar no minimo 8 digitos alfa numérico com caracteres especiais)
E-mail para envio de Relatório de Backup: email@dominio.com.br (OFFICE 365)
Senha do E-mail: *******
"
read -r -a HOSTNAME -p "Hostname Realm: "
HOSTNAMEUP=${HOSTNAME^^}
if [ -z "$HOSTNAME" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a NOMESRV -p "Nome do Servidor: "
NOMESRVUP=${NOMESRV^^}
if [ -z "$NOMESRV" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a REALM -p "Dominio Realm: "
REALMUP=${REALM^^}
if [ -z "$REALM" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a NETBIOS -p "Dominio NETBIOS: "
NETBIOSUP=${NETBIOS^^}
if [ -z "$NETBIOS" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a OU -p "Nome da OU Raiz: "
if [ -z "$OU" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a ENDERECOIP -p "Endereço IP do servidor: "
if [ -z "$ENDERECOIP" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a RANGE -p "Range de rede: "
if [ -z "$RANGE" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
read -r -a INTERFACE -p "Interface de rede: "
if [ -z "$INTERFACE" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
while true; do
read -r -s -p "Senha do Administrator: " SENHA
echo
read -r -s -p "Conforme a senha novamente: " SENHA2
[ "$SENHA" = "$SENHA2" ] && break
echo ""
echo "Tente novamente"
echo ""
done
echo ""
read -r -a EMAIL -p "E-mail para envio de Relatório de Backup: "
if [ -z "$EMAIL" ]; then
echo "CAMPO EM BRANCO FAVOR INICIAR INSTALAÇÃO NOVAMENTE..."
exit 0
fi
while true; do
read -r -s -p "Senha do E-mail: " SENHAEMAIL
echo ""
read -r -s -p "Confirme a senha novamente: " SENHAEMAIL2
echo ""
[ "$SENHAEMAIL" = "$SENHAEMAIL2" ] && break
echo ""
echo "Tente novamente"
echo ""
done
echo ""
clear
$ARTE
echo "SETANDO HOSTNAME..."
sleep 5s
hostnamectl set-hostname "$HOSTNAME"
sleep 3s
clear
$ARTE
read -r -p  "VAMOS AGORA INSTALAR OS PACOTES NECESSÁRIO PRESSIONE <ENTER> PARA CONTINNUAR ou <CTRL+C) PARA CANCELAR"
yum install epel-release centos-release-gluster wget vim -y
yum install -y https://download2.veeam.com/veeam-release-el7-1.0.7-1.x86_64.rpm
yum update -y
yum install -y gcc gcc-c++ make python36-devel python36-dns git heimdal-devel gdb libtirpc-devel lmdb-devel gnutls-devel libacl-devel libattr-devel readline-devel zlib-devel libxslt-devel libcmocka-devel popt-devel gpgme-devel libbsd-devel jansson-devel perl-Parse-Yapp libarchive-devel gamin-devel openldap-devel pam-devel avahi-devel libcap-devel libaio-devel valgrind-devel gettext-devel docbook-style-xsl libunwind-devel systemd-devel perl-ExtUtils-MakeMaker xfsprogs-devel dbus-devel glusterfs-devel glusterfs-api-devel libtasn1-tools nss_wrapper pam_wrapper resolv_wrapper socket_wrapper uid_wrapper fuse-devel oddjob-mkhomedir bind bind-sdb bind-utils patch heimdal-path heimdal-workstation postfix cyrus-sasl-plain mailx hplip ghostscript.x86_64 hplip-common.x86_64 lmdb-devel gpgme-devel libarchive-devel foomatic jansson-devel kernel-devel libsmbclient-devel openldap-clients veeam sshpass
yum install -y http://ftp.unicamp.br/pub/centos/7/storage/x86_64/nfs-ganesha-28/lttng-ust-2.10.0-1.el7.x86_64.rpm
clear
$ARTE
echo "VAMOS AGORA BAIXAR COMPILAR O SAMBA 4.11.1 (VA TOMAR UM CAFEZINHO...)"
sleep 7s
mv /etc/samba/smb.conf /etc/samba/smb.conf.old
cd /usr/local/src
wget https://download.samba.org/pub/samba/stable/samba-4.11.1.tar.gz
tar -zxvf samba-4.11.1.tar.gz
cd samba-4.11.1


./configure -j 4 --progress --prefix /usr --enable-fhs --sysconfdir=/etc --localstatedir=/var --with-privatedir=/var/lib/samba/private --with-piddir=/var/run/samba --with-automount --datadir=/usr/share --with-lockdir=/var/run/samba --with-statedir=/var/lib/samba --with-cachedir=/var/cache/samba --with-systemd
make -j 4
make install



echo "exclude=samba*" >> /etc/yum.conf

ldconfig
ldconfig
ldconfig
ldconfig
clear



$ARTE
echo "PROVISIONANDO O DOMÍNIO"
samba-tool domain provision --realm="$REALMUP" --domain="$NETBIOSUP" --adminpass="$SENHA" --server-role=dc --dns-backend=BIND9_DLZ --option="interfaces=lo $INTERFACE" --option="bind interfaces only=yes" --use-rfc2307
read -r -p  "VERIFIQUE AS INFORMAÇÕES E APERTE <ENTER> PARA CONTINUAR "
echo "[kdc]
  check-ticket-addresses = false" >> /var/lib/samba/private/krb5.conf
rm -rf /etc/krb5.conf
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
chown root.named /etc/krb5.conf

clear
$ARTE
echo "CONFIGURANDO NTP CHRONY"
echo -n >> /etc/chrony.conf

cat > /etc/chrony.conf << EOF
server 0.br.pool.ntp.org iburst
server 1.br.pool.ntp.org iburst
server 2.br.pool.ntp.org iburst
server 3.br.pool.ntp.org iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
#local stratum 10
keyfile /etc/chrony.keys
logdir /var/log/chrony
log measurements statistics tracking
maxupdateskew 100.0
hwclockfile /etc/adjtime

bindcmdaddress $ENDERECOIP
allow $RANGE

ntpsigndsocket  /var/lib/samba/ntp_signd/
EOF

mkdir /var/lib/samba/ntp_signd/
chmod 0750 /var/lib/samba/ntp_signd/
chown root.chrony /var/lib/samba/ntp_signd/
#
systemctl enable --now chronyd
sleep 5s
clear
$ARTE
echo "CONFIGURANDO O BIND9_DLZ (NAMED)"
cat >> /etc/sysconfig/named << EOF
OPTIONS="-4"
EOF
echo -n > /etc/named.conf
cat >> /etc/named.conf << EOF
options {
  listen-on port 53 { any; };
  listen-on-v6 port 53 { none; };
  directory "/var/named";
  dump-file "/var/named/data/cache_dump.db";
  statistics-file "/var/named/data/named_stats.txt";
  memstatistics-file "/var/named/data/named_mem_stats.txt";
  allow-query { any; };

  recursion yes;
  allow-recursion { any; };

  allow-transfer { $RANGE; };

  dnssec-enable no;
  dnssec-validation no;

  managed-keys-directory "/var/named/dynamic";
  pid-file "/run/named/named.pid";
  tkey-gssapi-keytab "/var/lib/samba/bind-dns/dns.keytab";
  
  forwarders {
         8.8.8.8;
         8.8.4.4;
};
};

logging {
  channel default_debug {
    file "data/named.run";
    severity dynamic;
  };
};

zone "." IN {
  type hint;
  file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
include "/var/lib/samba/bind-dns/named.conf";
EOF
echo "KRB5RCACHETYPE=\"none\"" >> /etc/sysconfig/named
systemctl enable --now named
systemctl status named
read -r -p  "VERIFIQUE O STATUS DO SERVIÇO NAMED E APERTE <ENTER> PARA CONTINUAR "
clear
$ARTE
echo -e "CONFIGURANDO ARQUIVO RESOLV.CONF..."
sleep 5s
cat >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE << EOF
DNS1=$ENDERECOIP
EOF
echo -n > /etc/resolv.conf
cat >> /etc/resolv.conf <<EOF
search $REALM
nameserver $ENDERECOIP
EOF
clear
$ARTE
echo -e "CONFIGURANDO ARQUIVO HOSTS..."
cat >> /etc/hosts << EOF
$ENDERECOIP $HOSTNAME $NOMESRV
EOF
sleep 5s
clear
$ARTE
echo -e "CONFIGURANDO /etc/nsswitch.conf..."
sleep 5s
sed -i 33d /etc/nsswitch.conf
sed -i 33d /etc/nsswitch.conf
sed -i 33d /etc/nsswitch.conf
cat >> /etc/nsswitch.conf <<EOF
passwd:     files winbind sss 
shadow:     files sss 
group:      files winbind sss 
EOF
sleep 5s
clear
$ARTE
echo -e "CRIANDO PASTA /Servidor, /Servidor/backup, /Servidor/Usuarios e /Servidor/Lixeira "
mkdir /Servidor
mkdir /Servidor/Lixeira
mkdir /Servidor/Usuarios
mkdir /Servidor/backup
mkdir /Servidor/backup/SAMBA4
mkdir /Servidor/backup/LOGS
mkdir /Servidor/Suporte
mkdir /Servidor/Suporte/Auditoria
touch /etc/rsyslog.d/auditsamba.conf
cat >> /etc/rsyslog.d/auditsamba.conf <<EOF
local5.notice /Servidor/Suporte/Auditoria/auditoria.txt
EOF
sleep 5s
clear
$ARTE
echo "CONFIGURANDO SMB.CONF"
echo -n > /etc/samba/smb.conf
cat >> /etc/samba/smb.conf <<EOF
# Global parameters
[global]
        netbios name = $NOMESRVUP
        realm = $REALMUP
        server role = active directory domain controller
        workgroup = $NETBIOSUP
		bind interfaces only = yes
        interfaces = lo $INTERFACE
				ldap server require strong auth = no
                server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
                idmap_ldb:use rfc2307 = yes
                winbind nss info = rfc2307
                winbind use default domain = yes
                winbind enum users = yes
                winbind enum groups = yes
                vfs objects = acl_xattr, recycle
                map acl inherit = Yes
                store dos attributes = Yes

################# Configura Lixeira para o Samba4 #################
                recycle:keeptree = yes
                recycle:versions = yes
                recycle:repository = /Servidor/Lixeira/%U
                recycle:exclude = *.tmp, *.log, *.obj, ~*.*, *.bak
                recycle:exclude_dir = tmp, cache, profiles

################# AUDITORIA #################

				log level = 0
                log file = /Servidor/Suporte/Auditoria/auditoria.txt
                max log size = 1048576
                strict sync = yes
                sync always = yes
                full_audit:success = mkdir, rmdir, read, pread, write, pwrite, rename, unlink, chmod, chown, open, opendir
                full_audit:prefix = %u|%I|%m|%p|%P|%S
                full_audit:failure = none
                full_audit:facility = local5
                full_audit:priority = notice

################# COMPARTILHAMENTOS #################

[netlogon]
        path = /var/lib/samba/sysvol/$REALM/scripts
        read only = No
        browseable = no
				
[sysvol]
        path = /var/lib/samba/sysvol
        read only = No
        browseable = no
		
[Usuarios]
        path = /Servidor/Usuarios
        read only = no
        browseable = no
		
[Lixeira]
        path = /Servidor/Lixeira
        read only = no
        browseable = no	
		
EOF
sleep 5s
clear
$ARTE
echo -e "CONFIGURANDO SYSTEMCTL SAMBA4 E STARTANDO O SERVIÇO"
cat >> /etc/systemd/system/samba.service <<EOF
[Unit]
Description=Samba4 AD DC
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
LimitNOFILE=16384
ExecStart=/usr/sbin/samba -D
ExecReload=/usr/bin/kill -HUP $MAINPID
PIDFile=/var/run/samba/samba.pid

[Install]
WantedBy=multi-user.target
EOF
systemctl enable samba
systemctl start samba
sleep 10s
systemctl status samba -l
read -r -p  "VERIFIQUE O STATUS DO SERVIÇO SAMBA E APERTE <ENTER> PARA CONTINUAR "
systemctl restart rsyslog
clear
$ARTE
echo "ATUALIZANDO DNS COM O  samba_dnsupdate --all-names --verbose"
systemctl restart named
systemctl restart samba
samba_dnsupdate --all-names --verbose
read -r -p  "VERIFIQUE O STATUS DA ATUALIZAÇÃO DNS E APERTE <ENTER> PARA CONTINUAR "
clear
$ARTE

echo -e "DIGITE SUA SENHA DE ADMINISTRATOR AGORA"
net rpc rights grant "$NETBIOSUP\Domain Admins" SeDiskOperatorPrivilege -U "$NETBIOSUP\administrator" 
net rpc rights grant "$NETBIOSUP\Domain Admins" SePrintOperatorPrivilege -U "$NETBIOSUP\administrator"
clear
$ARTE
echo "CONFIGURANDO AUDITORIA E ADICIONANDO AO CRONTAB"
touch /sbin/auditoria.sh
cat > /sbin/auditoria.sh << \EOF
#!/bin/bash
MES=$(date '+%B');
ANO=$(date '+%Y');
mkdir -p /Servidor/Suporte/Auditoria/AUDITORIAS_ANTERIORES/${ANO}/
/usr/local/bin/rar a /Servidor/Suporte/Auditoria/AUDITORIAS_ANTERIORES/${ANO}/AUDITORIA-${MES}.rar /Servidor/Suporte/Auditoria/auditoria*
rm -rf /Servidor/Suporte/Auditoria/auditoria*
systemctl restart rsyslog
chown root."Domain Admins" /Servidor/Suporte/Auditoria/ -R
EOF
chmod 777 /sbin/auditoria.sh

touch /sbin/samba_backup
chmod +x /sbin/samba_backup
cat > /sbin/samba_backup << \EOF
#!/bin/sh
#
# Copyright (C) Matthieu Patou <mat@matws.net> 2010-2011
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Revised 2013-09-25, Brian Martin, as follows:
#    - Allow retention period ("DAYS") to be specified as a parameter.
#    - Allow individual positional parameters to be left at the default
#      by specifying "-"
#    - Use IS0 8601 standard dates (yyyy-mm-dd instead of mmddyyyy).
#    - Display tar exit codes when reporting errors.
#    - Don't send error messages to /dev/null, so we know what failed.
#    - Suppress useless tar "socket ignored" message.
#    - Fix retention period bug when deleting old backups ($DAYS variable
#      could be set, but was ignored).



FROMWHERE=/var/lib/samba
WHERE=/Servidor/backup/SAMBA4
DAYS=90				# Set default retention period.
if [ -n "$1" ] && [ "$1" = "-h" -o "$1" = "--usage" ]; then
	echo "samba_backup [provisiondir] [destinationdir] [retpd]"
	echo "Will backup your provision located in provisiondir to archive stored"
	echo "in destinationdir for retpd days. Use - to leave an option unchanged."
	echo "Default provisiondir: $FROMWHERE"
	echo "Default destinationdir: $WHERE"
	echo "Default destinationdir: $DAYS"
	exit 0
fi

[ -n "$1" -a "$1" != "-" ]&&FROMWHERE=$1	# Use parm or default if "-".  Validate later.
[ -n "$2" -a "$2" != "-" ]&&WHERE=$2		# Use parm or default if "-".  Validate later.
[ -n "$3" -a "$3" -eq "$3" 2> /dev/null ]&&DAYS=$3	# Use parm or default if non-numeric (incl "-").

DIRS="private etc sysvol"
#Number of days to keep the backup
WHEN=`date +%Y-%m-%d`	# ISO 8601 standard date.

if [ ! -d $WHERE ]; then
	echo "Missing backup directory $WHERE"
	exit 1
fi

if [ ! -d $FROMWHERE ]; then
	echo "Missing or wrong provision directory $FROMWHERE"
	exit 1
fi

cd $FROMWHERE
for d in $DIRS;do
	relativedirname=`find . -type d -name "$d" -prune`
	n=`echo $d | sed 's/\//_/g'`
	if [ "$d" = "private" ]; then
		find $relativedirname -name "*.ldb.bak" -exec rm {} \;
		for ldb in `find $relativedirname -name "*.ldb"`; do
			tdbbackup $ldb
			Status=$?	# Preserve $? for message, since [ alters it.
			if [ $Status -ne 0 ]; then
				echo "Error while backing up $ldb - status $Status"AUDITORIA
				exit 1
			fi
		done
		# Run the backup.
		#    --warning=no-file-ignored set to suppress "socket ignored" messages.
		tar cjf ${WHERE}/samba4_${n}.${WHEN}.tar.bz2  $relativedirname --exclude=\*.ldb --warning=no-file-ignored --transform 's/.ldb.bak$/.ldb/' --xattrs
		Status=$?	# Preserve $? for message, since [ alters it.
		if [ $Status -ne 0 -a $Status -ne 1 ]; then	# Ignore 1 - private dir is always changing.
			echo "Error while archiving ${WHERE}/samba4_${n}.${WHEN}.tar.bz2 - status = $Status"
			exit 1
		fi
		find $relativedirname -name "*.ldb.bak" -exec rm {} \;
	else
		# Run the backup.
# –warning=no-file-ignored set to suppress “socket ignored” messages

if [ "$d" = "etc" ]; then
tar cjf ${WHERE}/${n}.${WHEN}.tar.bz2 "/etc/samba/" --warning=no-file-ignored --xattrs
Status=$? # Preserve $? for message, since [ alters it. #(CASO SEJA “o diretorio etc”) 
else
tar cjf ${WHERE}/${n}.${WHEN}.tar.bz2 $relativedirname --warning=no-file-ignored --xattrs
Status=$?  # Preserve $? for message, since [ alters it (CASO seja outro)
fi
	fi
done

find $WHERE -name "samba4_*bz2" -mtime +$DAYS -exec rm  {} \;
EOF


crontab -l > mycron
echo "59 23 28-31 * * [ &quot;$(date +%d -d tomorrow)&quot; = &quot;01&quot; ] &amp;&amp; /sbin/auditoria.sh" >> mycron
crontab mycron
rm -f mycron
sleep 5s
clear
$ARTE
echo -e "SETANDO PERMISSÕES NAS PASTAS DE USUÁRIO E LIXEIRA"
chown -R root."Domain Admins" /Servidor/
samba-tool ntacl set "O:LAG:DAD:PAI(A;OICI;0x001f01ff;;;DA)(A;;0x001200a1;;;DU)" /Servidor/Usuarios
samba-tool ntacl set "O:LAG:DAD:PAI(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001201bf;;;DU)" /Servidor/Lixeira
samba-tool ntacl set "O:LAG:DAD:PAI(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001201bf;;;DU)" /Servidor/Suporte
sleep 5s
clear
$ARTE
echo -e "ATIVANDO COMPLEXIDADE DE SENHA E SETANDO PARA SENHA COM NO MINIMO 6 DIGITOS TEMPO 60 DIAS PARA TROCA E 3 SENHAS GRAVADAS"
sleep 5s
samba-tool domain passwordsettings set --min-pwd-length=6
samba-tool domain passwordsettings set --min-pwd-age=0
samba-tool domain passwordsettings set --max-pwd-age=60
samba-tool domain passwordsettings set --history-length=3
clear
$ARTE
echo -e "CONFIGURANDO OUs"
sleep 7s
samba-tool ou create OU="$OU"
samba-tool ou create OU=USUARIOS,OU="$OU"
samba-tool ou create OU=GRUPOS,OU="$OU"
clear
$ARTE


sleep 5s
clear
echo -n > /etc/samba/smb.conf
cat >> /etc/samba/smb.conf <<EOF
# Global parameters
[global]
        netbios name = $NOMESRVUP
        realm = $REALMUP
        server role = active directory domain controller
        workgroup = $NETBIOSUP
		bind interfaces only = yes
        interfaces = lo $INTERFACE
				ldap server require strong auth = no
                server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
                idmap_ldb:use rfc2307 = yes
                winbind nss info = rfc2307
                winbind use default domain = yes
                winbind enum users = yes
                winbind enum groups = yes
                vfs objects = acl_xattr, recycle, full_audit
                map acl inherit = Yes
                store dos attributes = Yes

################# Configura Lixeira para o Samba4 #################
                recycle:keeptree = yes
                recycle:versions = yes
                recycle:repository = /Servidor/Lixeira/%U
                recycle:exclude = *.tmp, *.log, *.obj, ~*.*, *.bak
                recycle:exclude_dir = tmp, cache, profiles

################# AUDITORIA #################

				log level = 0
                log file = /Servidor/Suporte/Auditoria/auditoria.txt
                max log size = 1048576
                strict sync = yes
                sync always = yes
                full_audit:success = mkdir, rmdir, read, pread, write, pwrite, rename, unlink, chmod, chown, open, opendir
                full_audit:prefix = %u|%I|%m|%p|%P|%S
                full_audit:failure = none
                full_audit:facility = local5
                full_audit:priority = notice

################# COMPARTILHAMENTOS #################

[netlogon]
        path = /var/lib/samba/sysvol/$REALM/scripts
        read only = No
        browseable = no
				
[sysvol]
        path = /var/lib/samba/sysvol
        read only = No
        browseable = no
		
[Usuarios]
        path = /Servidor/Usuarios
        read only = no
        browseable = no
		
[Lixeira]
        path = /Servidor/Lixeira
        read only = no
        browseable = no	
	
EOF
clear
$ARTE
echo -e "CONFIGURANDO ENVIO DE E-MAIL"
sleep 10s
cat >> /etc/postfix/main.cf <<EOF
relayhost = [smtp.office365.com]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
# Corrige o problema do sender
sender_canonical_classes = envelope_sender, header_sender
sender_canonical_maps =  regexp:/etc/postfix/sender_canonical_maps
smtp_header_checks = regexp:/etc/postfix/header_check
EOF
touch /etc/postfix/sasl_passwd
cat >> /etc/postfix/sasl_passwd <<EOF
[smtp.office365.com]:587 $EMAIL:$SENHAEMAIL
EOF
postmap /etc/postfix/sasl_passwd
chown root:postfix /etc/postfix/sasl_passwd*
chmod 640 /etc/postfix/sasl_passwd*
touch /etc/postfix/sender_canonical_maps
cat >> /etc/postfix/sender_canonical_maps <<EOF
/.+/    $EMAIL
EOF
touch /etc/postfix/header_check
cat >> /etc/postfix/header_check <<EOF
/From:.*/ REPLACE From: $EMAIL
EOF
systemctl enable postfix
systemctl start postfix
echo "Este é um teste" | mail -s "Mensagem de Teste" $EMAIL
clear
$ARTE

echo -e "PREPARANDO VEEAMBACKUP"
sleep 5s
mkdir /etc/veeam/scripts/
touch /etc/veeam/scripts/pre.sh
touch /etc/veeam/scripts/veeam_mail_template.html
touch /etc/veeam/scripts/email.sh
chmod 777 /etc/veeam/scripts/ -R

cat > /etc/veeam/scripts/pre.sh << \EOF
#!/bin/bash
WHEN=`date +%d-%m-%Y`
systemctl stop samba >> /dev/null
/sbin/samba_backup >> /dev/null
systemctl start samba >> /dev/null
for i in `find /Servidor/Lixeira/* -maxdepth 0 -type d -ctime +6 -print`; do echo -e "Deleting directory $i";rm -rf $i; done #LIMPA A LIXEIRA A CADA 6 DIAS
mkdir /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}
rsync -av /etc/hosts /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/resolv.conf /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/sysconfig/network-scripts/ifcfg-en* /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/passwd /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/group /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/shadow /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
rsync -av /etc/hostname /Servidor/backup/SAMBA4/ETC-CONFS-${WHEN}/ >> /Servidor/backup/LOGS/LOG-${WHEN}.txt
#rsync -XAavz /Servidor/ /backup/DADOS >> /backup/LOGS/LOG-${WHEN}.txt
find /Servidor/backup/SAMBA4/* -ctime +90 -exec rm -rf {} \; >> /Servidor/backup/LOGS/LOG-${WHEN}.txt # APAGAR ARQUIVOS E PASTAS COM MAIS DE 90 DIAS
find /Servidor/backup/LOGS/* -ctime +90 -exec rm -rf {} \; # APAGA LOGS COM MAIS DE 90 DIAS
exit 0
EOF

cat > /etc/veeam/scripts/email.sh << \EOF
#!/bin/bash
# version 0.4.2
JOBNAME="NOMEDAEMPRESAAQUI-DADOS"
EMAILTO="SEUEMAIL"
EMAILFROM="EMAILDEENVIO"
HTMLTEMPLATE="/etc/veeam/scripts/veeam_mail_template.html"

if [ "$1" == "--bg" ]; then
 sleep 30
fi

VC=$(which veeamconfig)
if [ ! "$VC" ]; then
	echo "No Veeam Agent for Linux installed!"
	exit
fi

SQLITE=$(which sqlite3)
if [ "$SQLITE" != "/usr/bin/sqlite3" ]; then
	apt-get install -y sqlite3
fi

BC=$(which bc)
if [ "$BC" != "/usr/bin/bc" ]; then
	apt-get install -y bc
fi

AGENT=$($VC -v)
# get last session id
SESSID=$($VC session list|grep -v "Total amount"|tail -1|awk '{print $3}')
SESSID=${SESSID:1:${#SESSID}-2}

# state 1=Running, 6=Success, 7=Failed, 9=Warning
# get data from sqlite db
SESSDATA=$(sqlite3 /var/lib/veeam/veeam_db.sqlite  "select start_time, end_time, state, progress_details from JobSessions order by start_time DESC limit 1;")
STARTTIME=$(echo $SESSDATA|awk -F'|' '{print $1}')
ENDTIME=$(echo $SESSDATA|awk -F'|' '{print $2}')
STATE=$(echo $SESSDATA|awk -F'|' '{print $3}')
DETAILS=$(echo $SESSDATA|awk -F'|' '{print $4}')

if [ ! "$1" == "--bg" ]; then 
 nohup $0 --bg >/dev/null &
	exit
fi
if [ "$STATE" == "6" ]; then SUCCESS=1; BGCOLOR="#00B050"; STAT="Success"; else SUCCESS=0; fi
if [ "$STATE" == "7" ]; then ERROR=1; BGCOLOR="#fb9895"; STAT="Failed"; else ERROR=0; fi
if [ "$STATE" == "9" ]; then WARNING=1; BGCOLOR="#fbcb95"; STAT="Warning"; else WARNING=0; fi

PROCESSED=$(echo $DETAILS|awk -F'processed_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
PROCESSED=$($BC <<< "scale=1; $PROCESSED/1024/1024/1024")" GB"
READ=$(echo $DETAILS|awk -F'read_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
READ=$($BC <<< "scale=1; $READ/1024/1024/1024")" GB"
TRANSFERRED=$(echo $DETAILS|awk -F'transferred_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
if [ $TRANSFERRED -gt 1073741824 ]; then
	TRANSFERRED=$($BC <<< "scale=1; $TRANSFERRED/1024/1024/1024")" GB"
else
	TRANSFERRED=$($BC <<< "scale=0; $TRANSFERRED/1024/1024")" MB"
fi
SPEED=$(echo $DETAILS|awk -F'processing_speed="' '{print $2}'|awk -F'"' '{print $1}')
SPEED=$($BC <<< "scale=1; $SPEED/1024/1024")
SOURCELOAD=$(echo $DETAILS|awk -F'source_read_load="' '{print $2}'|awk -F'"' '{print $1}')
SOURCEPLOAD=$(echo $DETAILS|awk -F'source_processing_load="' '{print $2}'|awk -F'"' '{print $1}')
NETLOAD=$(echo $DETAILS|awk -F'network_load="' '{print $2}'|awk -F'"' '{print $1}')
TARGETLOAD=$(echo $DETAILS|awk -F'target_write_load="' '{print $2}'|awk -F'"' '{print $1}')

if [ "$SOURCELOAD" -gt "$SOURCEPLOAD" ] && [ "$SOURCELOAD" -gt "$NETLOAD" ] && [ "$SOURCELOAD" -gt "$TARGETLOAD" ]; then
	BOTTLENECK="Source"
fi
if [ "$SOURCEPLOAD" -gt "$SOURCELOAD" ] && [ "$SOURCEPLOAD" -gt "$NETLOAD" ] && [ "$SOURCEPLOAD" -gt "$TARGETLOAD" ]; then
	BOTTLENECK="Source CPU"
fi
if [ "$NETLOAD" -gt "$SOURCELOAD" ] && [ "$NETLOAD" -gt "$SOURCEPLOAD" ] && [ "$NETLOAD" -gt "$TARGETLOAD" ]; then
	BOTTLENECK="Network"
fi
if [ "$TARGETLOAD" -gt "$SOURCELOAD" ] && [ "$TARGETLOAD" -gt "$SOURCEPLOAD" ] && [ "$TARGETLOAD" -gt "$NETLOAD" ]; then
	BOTTLENECK="Target"
fi

DURATION=$(date -d "0 $ENDTIME sec - $STARTTIME sec" +"%H:%M:%S")
START=$(date -d "@$STARTTIME" +"%A, %d %B %Y %H:%M:%S")
END=$(date -d "@$ENDTIME" +"%A, %d.%m.%Y %H:%M:%S")
STIME=$(date -d "@$STARTTIME" +"%H:%M:%S")
ETIME=$(date -d "@$ENDTIME" +"%H:%M:%S")

# get session error
ERRLOG=$($VC session log --id $SESSID|egrep 'error|warn'|sed ':a;N;$!ba;s/\n/<br>/g'|sed -e "s/ /\&nbsp;/g")
ERRLOG=$(printf "%q" $ERRLOG)

# create temp file for mail
TEMPFILE=/tmp/email.html

# uppercase hostname
HN=${HOSTNAME^^}

# build email
echo "From: $EMAILFROM
To: $EMAILTO
Subject: [$STAT] $HN - $START
MIME-Version: 1.0
Content-Type: text/html

" > $TEMPFILE

# debug output
#echo -e -n "HN: $HN\nSTAT: $STAT\nBGCOLOR: $BGCOLOR\nSTART: $START\nSUCCESS: $SUCCESS\nERROR: $ERROR\nWARNING: $WARNING\nSTIME: $STIME\nETIME: $ETIME\nREAD: $READ\nTRANSFERRED: $TRANSFERRED\nDURATION: $DURATION\nPROCESSED: $PROCESSED\nBOTTLENECK: $BOTTLENECK\nERRLOG: $ERRLOG\nSPEED: $SPEED\n"

sed -e "s/XXXHOSTNAMEXXX/$HN/g" -e "s/XXXSTATXXX/$STAT/g" -e "s/XXXBGCOLORXXX/$BGCOLOR/g" -e "s/XXXBACKUPDATETIMEXXX/$START/g" -e "s/XXXSUCCESSXXX/$SUCCESS/g" -e "s/XXXERRORXXX/$ERROR/g" -e "s/XXXWARNINGXXX/$WARNING/g" -e "s/XXXSTARTXXX/$STIME/g" -e "s/XXXENDXXX/$ETIME/g" -e "s/XXXDATAREADXXX/$READ/g" -e "s/XXXREADXXX/$READ/g" -e "s/XXXTRANSFERREDXXX/$TRANSFERRED/g" -e "s/XXXDURATIONXXX/$DURATION/g" -e "s/XXXSTATUSXXX/$STAT/g" -e "s/XXXTOTALSIZEXXX/$PROCESSED/g" -e "s/XXXBOTTLENECKXXX/$BOTTLENECK/g" -e "s|XXXDETAILSXXX|$ERRLOG|g" -e "s/XXXRATEXXX/$SPEED MB\/s/g" -e "s/XXXBACKUPSIZEXXX/$TRANSFERRED/g" -e "s/XXXAGENTXXX/$AGENT/g" $HTMLTEMPLATE >> $TEMPFILE

# send email
cat $TEMPFILE | sendmail -t
rm $TEMPFILE

exit
EOF

clear
$ARTE
echo "POR FAVOR PREENCHA OS ITENS PEDIDOS PARA O ENVIO DE EMAIL"
sleep 7s
vim /etc/veeam/scripts/email.sh


cat > /etc/veeam/scripts/veeam_mail_template.html << \EOF
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">
</head>
<body text="#000000" bgcolor="#FFFFFF">
<div class="moz-forward-container">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<table style="border-collapse: collapse;" cellspacing="0" cellpadding="0" width="100%" border="0">
<tbody>
<td style="border:none; padding: 0px;font-family: Tahoma;font-size: 12px;">
<table style="border-collapse: collapse;" cellspacing="0" cellpadding="0" width="100%" border="0">
<tbody>
<tr style="height:70px">
<td style="width: 80%;border: none;background-color: XXXBGCOLORXXX;color: White;font-weight: bold;font-size: 16px;height: 70px;vertical-align: bottom;padding: 0 0 17px 15px;font-family: Tahoma;">Agent Backup job: Backup Job XXXHOSTNAMEXXX<div class="jobDescription" style="margin-top: 5px;font-size: 12px;"> Veeam Agent for Linux </div> </td>
<td style="background-color: XXXBGCOLORXXX;color: White;font-weight: bold;font-size: 16px;height: 70px;vertical-align: bottom;padding: 0 0 17px 15px;font-family: Tahoma;padding-bottom: 42px;">XXXSTATXXX</td>
</tr>
<tr>
<td colspan="2" style="border: none; padding: 0px;font-family: Tahoma;font-size: 12px;">
<table class="inner" style="margin: 0px;border-collapse: collapse;" cellspacing="0" cellpadding="0" width="100%" border="0">
<tbody>
<tr style="height: 17px;">
<td colspan="9" class="sessionDetails" style="border-style: solid; border-color:#a7a9ac; border-width: 1px 1px 0 1px;height: 35px;background-color: #f3f4f4;font-size: 16px;vertical-align: middle;padding: 5px 0 0 15px;color: #626365; font-family: Tahoma;"><span>XXXBACKUPDATETIMEXXX</span></td>
</tr>
<tr style="height: 17px;">
<td style="width: 1%;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Success</b></td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXSUCCESSXXX</td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Start time</b></td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXSTARTXXX</td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Total size</b></td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXTOTALSIZEXXX</td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Backup size</b></td>
<td style="width:75px;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXBACKUPSIZEXXX</td>
<td rowspan="3" style="border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;vertical-align: top;"><span class="small_label" style="font-size: 10px;"></span></td>
</tr>
<tr style="height: 17px;">
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Warning</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;">XXXWARNINGXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>End time</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXENDXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Data read</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXDATAREADXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Bottleneck</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXBOTTLENECKXXX</td>
</tr>
<tr style="height: 17px;">
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Error</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;">XXXERRORXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Duration</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXDURATIONXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Transferred</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXTRANSFERREDXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Processing rate:</b></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXRATEXXX</td>
</tr>
<tr style="height: 17px;">
<td colspan="9" style="height: 35px;background-color: #f3f4f4;font-size: 16px;vertical-align: middle;padding: 5px 0 0 15px;color: #626365; font-family: Tahoma;border: 1px solid #a7a9ac;" nowrap="nowrap"> Details </td>
</tr>
<tr class="processObjectsHeader" style="height: 23px">
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Name</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Status</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Start
time</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>End
time</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Size</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Read</b></td>
<td style="width:1%;background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Transferred</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><b>Duration</b></td>
<td style="background-color: #e3e3e3;padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;border-top: none;font-family: Tahoma;font-size: 12px;"><b>Details</b></td>
</tr>
<tr style="height: 17px;">
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXHOSTNAMEXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap"><span style="color: XXXBGCOLORXXX;">XXXSTATUSXXX</span></td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXSTARTXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXENDXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXTOTALSIZEXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXREADXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXTRANSFERREDXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;" nowrap="nowrap">XXXDURATIONXXX</td>
<td style="padding: 2px 3px 2px 3px;vertical-align: top;border: 1px solid #a7a9ac;font-family: Tahoma;font-size: 12px;"><span class="small_label" style="font-size: 10px;">XXXDETAILSXXX</span></td>
</tr>
</tbody>
</table>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</tbody>
</table>
</div>
<br>
<div style="color: #626365; font-family: Tahoma;font-size: 12px;">Veeam Agent for Linux XXXAGENTXXX</div>
</body>
</html>
EOF
clear
$ARTE
echo -e "CONFIGURANDO SELINUX E FIREWALLD, POR FAVOR AGUARDE"
sleep 10s
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --zone=public --add-service=samba
firewall-cmd --add-port=53/tcp --permanent
firewall-cmd --add-port=53/udp --permanent
firewall-cmd --add-port=88/tcp --permanent
firewall-cmd --add-port=88/udp --permanent
firewall-cmd --add-port=135/tcp --permanent
firewall-cmd --add-port=137-138/udp --permanent
firewall-cmd --add-port=139/tcp --permanent
firewall-cmd --add-port=389/tcp --permanent
firewall-cmd --add-port=389/udp --permanent
firewall-cmd --add-port=445/tcp --permanent
firewall-cmd --add-port=464/tcp --permanent
firewall-cmd --add-port=464/udp --permanent
firewall-cmd --add-port=636/tcp --permanent
firewall-cmd --add-port=3268-3269/tcp --permanent
firewall-cmd --add-port=49152-49175/tcp --permanent
firewall-cmd --add-port=5938/tcp --permanent
firewall-cmd --add-port=24007/tcp --permanent
firewall-cmd --reload
restorecon -vvRF /
setsebool -P named_write_master_zones 1
semanage fcontext -a -t named_cache_t "/var/lib/samba/bind-dns/dns(/.*)?"
restorecon -R -v /var/lib/samba/bind-dns/dns
setenforce 1
systemctl stop samba
systemctl stop named
clear
$ARTE
systemctl start named
systemctl status named -l
read -r -p  "CONFIRME SE O SERVIÇO DO NARMED SUBIU CORRETAMENTE E APERTE <ENTER>"
clear
$ARTE
systemctl start samba
sleep 10s
systemctl status samba -l
read -r -p  "CONFIRME SE O SERVIÇO DO SAMBA SUBIU CORRETAMENTE E APERTE <ENTER>"
clear
$ARTE
read -r -p  "INSTALAÇÃO FINALIZADA COM SUCESSO

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


PRESSIONE <ENTER> PARA REINICIAR O SISTEMA OU <CTRL+C> PARA FINALIZAR SEM REINICIAR
"
reboot
echo "================================================"
;;
    2)  
clear
$ARTE
echo "
ESSA E UMA VERSAO GRATUITA PARA ACESSO COMPLETO ENTRE EM CONTATO ATRAVES DO E-MAIL yuri.bucci@outlook.com
"
echo "================================================"
exit
;;
    3)  
clear
$ARTE
echo "
ESSA E UMA VERSAO GRATUITA PARA ACESSO COMPLETO ENTRE EM CONTATO ATRAVES DO E-MAIL yuri.bucci@outlook.com
"
echo "================================================"
exit
;;
    4)  
clear
$ARTE
echo "
ESSA E UMA VERSAO GRATUITA PARA ACESSO COMPLETO ENTRE EM CONTATO ATRAVES DO E-MAIL yuri.bucci@outlook.com
"
echo "================================================"
exit
;;
    5)  
clear
$ARTE
echo "
ESSA E UMA VERSAO GRATUITA PARA ACESSO COMPLETO ENTRE EM CONTATO ATRAVES DO E-MAIL yuri.bucci@outlook.com
"
echo "================================================"
exit
;;
    6)  
clear
$ARTE
echo "
ESSA E UMA VERSAO GRATUITA PARA ACESSO COMPLETO ENTRE EM CONTATO ATRAVES DO E-MAIL yuri.bucci@outlook.com
"
echo "================================================"
exit
;;
*)
        echo "Opção inválida!"
esac
done

}
menu
