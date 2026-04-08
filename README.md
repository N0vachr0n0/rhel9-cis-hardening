# cis-harden.sh — Documentation

> Script de remédiation CIS Benchmark Level 1 pour RHEL 9 — 29 sections couvrant le durcissement filesystem, kernel, SSH, PAM (faillock, pwquality, historique MDP), AIDE, sudo, crypto policies et journald. Compatible FreeIPA et Red Hat Satellite. Supporte `--dry-run` et l'exécution par section.

**Contexte :** VM rattachée à **FreeIPA** + **Red Hat Satellite**

---

## Table des matières

1. [Prérequis](#prérequis)
2. [Exécution du script](#exécution-du-script)
3. [Options](#options)
4. [Description des 29 sections](#description-des-29-sections)
5. [Contexte FreeIPA — points d'attention](#contexte-freeipa--points-dattention)
6. [Contexte Satellite — gpgcheck](#contexte-satellite--gpgcheck)
7. [Findings restants après le script](#findings-restants-après-le-script)
8. [Actions manuelles post-exécution](#actions-manuelles-post-exécution)

---

## Prérequis

- RHEL 9 (ou AlmaLinux 9 / Rocky Linux 9)
- Exécution en **root**
- `authselect` configuré avec un profil `sssd` ou `ipa` (requis pour les sections PAM)
- Vérifier avant exécution : `authselect current`

---

## Exécution du script

```bash
# Rendre exécutable
chmod +x cis-harden.sh

# Afficher l'aide
./cis-harden.sh --help

# Simuler TOUTES les sections sans rien modifier (recommandé avant prod)
./cis-harden.sh --dry-run --run

# Appliquer toutes les sections (demande confirmation)
./cis-harden.sh --run

# Appliquer sans confirmation interactive
./cis-harden.sh --run --yes

# Appliquer une seule section
./cis-harden.sh --section 24 --yes

# Dry-run d'une section
./cis-harden.sh --dry-run --section 21
```

> **Après exécution :** un redémarrage est recommandé (modules kernel, sysctl, crypto-policies, journald).

---

## Options

| Option | Description |
|---|---|
| `--run` | Applique toutes les sections (1 à 29) |
| `--section NUM` | Applique uniquement la section NUM |
| `--dry-run` | Simule sans appliquer aucun changement |
| `--yes` | Pas de confirmation interactive |
| `--help`, `-h` | Affiche l'aide |

---

## Description des 29 sections

### Section 1 — Filesystem / Partitions
**Règle CIS :** *Ensure /tmp Located On Separate Partition*

Active `tmp.mount` (systemd tmpfs) si `/tmp` n'est pas déjà sur une partition séparée ou tmpfs. Le montage tmpfs est transparent pour les applications et conforme CIS.

```
systemctl enable --now tmp.mount
```

> Si `/tmp` est sur une partition physique dédiée, la section détecte déjà la conformité et ne modifie rien.

---

### Section 2 — Modules kernel désactivés
**Règles CIS :** *Disable Mounting of cramfs / freevxfs / hfs / hfsplus / jffs2 / usb-storage*

Crée des fichiers `/etc/modprobe.d/<module>.conf` avec `install <mod> /bin/false` et `blacklist <mod>`. Les modules inutilisés représentent une surface d'attaque (ex: usb-storage pour prévenir les exfiltrations via USB).

**Effet immédiat :** déchargement live si le module est chargé. **Persistance :** au prochain reboot.

---

### Section 3 — Services à désactiver
**Règles CIS :** *Disable rpcbind / nftables / Bluetooth / autofs*

| Service | Raison |
|---|---|
| `rpcbind` | Inutile si pas de NFS/RPC. Réduit l'exposition réseau |
| `nftables` | Remplacé par `firewalld` (les deux ensemble créent des conflits) |
| `bluetooth` | Vecteur d'attaque sur serveurs physiques |
| `autofs` | Monte automatiquement des partitions réseau — risque de montage malveillant |

---

### Section 4 — Sudo logfile
**Règle CIS :** *Ensure Sudo Logfile Exists — /var/log/sudo.log*

Ajoute `Defaults logfile=/var/log/sudo.log` dans `/etc/sudoers`. Toutes les commandes exécutées via `sudo` sont tracées (qui, quand, quelle commande).

---

### Section 5 — Firewalld loopback
**Règles CIS :** *Configure Firewalld to Trust / Restrict Loopback Traffic*

- Ajoute l'interface `lo` à la zone `trusted`
- Ajoute des règles `rich-rule` pour rejeter tout trafic source 127.0.0.1/::1 vers une destination différente

Prévient les attaques de redirection de trafic loopback.

---

### Section 6 — Paramètres sysctl réseau (21 paramètres)
**Règles CIS :** IPv4/IPv6 hardening + ASLR + ptrace

| Paramètre | Valeur | Effet |
|---|---|---|
| `net.ipv4.ip_forward` | 0 | Désactive le routage IP |
| `net.ipv4.conf.all.send_redirects` | 0 | Pas de redirections ICMP sortantes |
| `net.ipv4.conf.all.accept_redirects` | 0 | Refuse redirections ICMP entrantes |
| `net.ipv4.conf.all.accept_source_route` | 0 | Refuse le source routing |
| `net.ipv4.conf.all.rp_filter` | 1 | Reverse path filtering (anti-spoofing) |
| `net.ipv4.tcp_syncookies` | 1 | Protection SYN flood |
| `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | Ignore broadcast ICMP (Smurf) |
| `net.ipv6.conf.all.*` | 0 | Désactive accept_ra / redirects / source_route / forwarding IPv6 |
| `kernel.randomize_va_space` | 2 | ASLR complet |
| `kernel.yama.ptrace_scope` | 1 | Restreint ptrace aux processus fils |

---

### Section 7 — Options de montage /dev/shm
**Règles CIS :** *Add nodev / noexec / nosuid to /dev/shm*

Ajoute les options dans `/etc/fstab` et remonte à chaud.

| Option | Effet |
|---|---|
| `nodev` | Interdit les fichiers device dans /dev/shm |
| `noexec` | Interdit l'exécution de binaires depuis /dev/shm |
| `nosuid` | Interdit les bits SUID/SGID dans /dev/shm |

---

### Section 8 — Options de montage /var
**Règles CIS :** *Add nodev / nosuid to /var*

Ajoute `nodev,nosuid` dans `/etc/fstab` pour `/var`. Applicable uniquement si `/var` est sur une partition séparée.

---

### Section 9 — Core dumps
**Règle CIS :** *Disable core dump backtraces / Disable storing core dump*

Configure `/etc/systemd/coredump.conf.d/complianceascode_hardening.conf` :
```ini
[Coredump]
ProcessSizeMax=0
Storage=none
```

Les core dumps peuvent contenir des données sensibles (mots de passe en mémoire, clés privées).

---

### Section 10 — Fichiers world-writable
**Règle CIS :** *Ensure No World-Writable Files Exist*

Parcourt toutes les partitions montées (hors `nodev`) et supprime les permissions `o+w` sur les fichiers réguliers. Prévient les modifications non autorisées de fichiers système.

---

### Section 11 — Contrôle d'accès at/cron
**Règles CIS :** *Ensure /etc/at.allow and /etc/cron.allow exist, at.deny/cron.deny absent*

- Crée `/etc/at.allow` (0640, root) et supprime `/etc/at.deny`
- Crée `/etc/cron.allow` (0600, root) et supprime `/etc/cron.deny`
- Corrige les permissions des répertoires `cron.d`, `cron.daily`, etc.

Seuls les utilisateurs listés dans `*.allow` peuvent utiliser at/cron.

---

### Section 12 — Durcissement SSH (13 directives)
**Règles CIS :** multiples directives SSH

Crée des fichiers drop-in dans `/etc/ssh/sshd_config.d/` :

| Directive | Valeur | Raison |
|---|---|---|
| `ClientAliveInterval` | 300 | Déconnecte les sessions inactives après 5 min |
| `ClientAliveCountMax` | 1 | 1 seul ping sans réponse avant déconnexion |
| `LoginGraceTime` | 60 | Limite le temps pour s'authentifier |
| `LogLevel` | VERBOSE | Journalisation des clés utilisées |
| `MaxAuthTries` | 4 | Max 4 tentatives d'authentification |
| `MaxSessions` | 10 | Limite les sessions multiplexées |
| `MaxStartups` | 10:30:60 | Limite les connexions non authentifiées |
| `Banner` | /etc/issue.net | Bannière légale obligatoire |
| `PermitRootLogin` | no | Interdit login direct en root |
| `KexAlgorithms` | -DH faibles | Supprime Diffie-Hellman group1/14/exchange-sha1 |
| `HostbasedAuthentication` | no | Désactive auth basée sur l'hôte |
| `IgnoreRhosts` | yes | Ignore .rhosts/.shosts |
| `PermitUserEnvironment` | no | Interdit les variables d'env SSH |

---

### Section 13 — PAM : désactiver nullok
**Règle CIS :** *Prevent Login to Accounts With Empty Password*

Supprime l'option `nullok` de `pam_unix.so` dans `system-auth` et `password-auth` via `authselect enable-feature without-nullok`. Empêche la connexion avec un mot de passe vide.

---

### Section 14 — SSH : PermitEmptyPasswords no
**Règle CIS :** *Disable SSH Access via Empty Passwords*

Ajoute `PermitEmptyPasswords no` dans les fichiers drop-in SSH. Complémentaire à la section 13.

---

### Section 15 — Bannières de connexion
**Règles CIS :** *Ensure Local/Remote Login Warning Banner Is Configured Properly*

Écrit dans `/etc/issue` et `/etc/issue.net` :
```
Authorized users only. All activity may be monitored and reported.
```

Requis légalement dans de nombreux contextes (obligation d'informer l'utilisateur de la surveillance).

---

### Section 16 — Qualité des mots de passe (dictcheck + maxrepeat)
**Règles CIS :** *Prevent Dictionary Words / Max Consecutive Repeating Characters*

Configure `/etc/security/pwquality.conf` :
- `dictcheck = 1` — vérifie contre le dictionnaire système
- `maxrepeat = 3` — max 3 caractères identiques consécutifs (ex: `aaa`)

---

### Section 17 — Umask par défaut (027)
**Règles CIS :** *Ensure Default Umask is Set Correctly*

Applique `umask 027` dans :
- `/etc/bashrc`
- `/etc/login.defs` (`UMASK 027`)
- `/etc/profile` et `/etc/profile.d/*.sh`

Umask 027 = nouveaux fichiers en 640, nouveaux répertoires en 750.

---

### Section 18 — Timeout de session interactive
**Règle CIS :** *Set Interactive Session Timeout*

Crée `/etc/profile.d/tmout.sh` avec `typeset -xr TMOUT=900`. Déconnecte automatiquement les sessions interactives inactives après **15 minutes**.

---

### Section 19 — Permissions fichiers init utilisateurs
**Règle CIS :** *All User Initialization Files Must Have Mode 0740 Or Less*

Parcourt les home directories des utilisateurs interactifs (UID ≥ 1000) et restreint les permissions des fichiers de configuration shell (`.bashrc`, `.bash_profile`, etc.) à 0740 maximum.

---

### Section 20 — Journald : compression des logs
**Règle CIS :** *Ensure journald is configured to compress large log files*

Ajoute `Compress=yes` dans `/etc/systemd/journald.conf.d/complianceascode_hardening.conf`. Réduit l'espace disque utilisé par les logs binaires journald.

---

### Section 21 — AIDE : contrôle d'intégrité des fichiers
**Règles CIS :** *Install AIDE / Configure AIDE to Verify Audit Tools / Configure Periodic Execution*

**AIDE** (Advanced Intrusion Detection Environment) calcule des checksums SHA-512 sur les fichiers système critiques et détecte toute modification non autorisée.

**Ce que fait cette section :**
1. Installe le package `aide`
2. Configure `/etc/aide.conf` pour surveiller les outils d'audit (`auditctl`, `auditd`, `ausearch`, `aureport`, `autrace`, `augenrules`)
3. Ajoute une vérification quotidienne via cron (`05 4 * * * root /usr/sbin/aide --check`)
4. Laisse `aide --init` **commenté** (à exécuter manuellement en maintenance)

**Impact ressources :**
- `aide --init` : scan complet du FS — CPU/IO intensif, 5 à 30 min
- `aide --check` (cron 04h05) : vérification différentielle, léger

**Pour initialiser la base (fenêtre de maintenance) :**
```bash
/usr/sbin/aide --init
cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

---

### Section 22 — Politique cryptographique CIS
**Règle CIS :** *Implement Custom Crypto Policy Modules for CIS Benchmark*

Crée 4 modules dans `/etc/crypto-policies/policies/modules/` et les active :

| Module | Effet |
|---|---|
| `NO-SSHCBC` | Désactive tous les chiffres CBC pour SSH |
| `NO-SSHWEAKCIPHERS` | Désactive 3DES-CBC, AES-*-CBC, CHACHA20-POLY1305 pour SSH |
| `NO-SSHWEAKMACS` | Désactive HMAC-MD5*, UMAC-64*, UMAC-128* pour SSH |
| `NO-WEAKMAC` | Désactive tous les MACs 128 bits sur le système |

Politique résultante : `DEFAULT:NO-SHA1:NO-SSHCBC:NO-SSHWEAKCIPHERS:NO-SSHWEAKMACS:NO-WEAKMAC`

> Compatible FreeIPA (utilise les crypto-policies système). Reboot requis.

---

### Section 23 — Durcissement sudo
**Règles CIS :** *sudo use_pty / Require Re-Authentication*

| Option | Valeur | Effet |
|---|---|---|
| `use_pty` | — | Empêche le détournement de terminal (TTY hijacking). sudo ne peut être utilisé que depuis un vrai terminal. |
| `timestamp_timeout` | 5 | Re-authentification toutes les 5 minutes (contre 15 min par défaut) |

Ajouté dans `/etc/sudoers` avec validation via `visudo -qcf`.

---

### Section 24 — PAM Faillock (verrouillage de compte)
**Règles CIS :** *Configure pam_faillock / Lock Accounts After Failed Attempts / Set Lockout Time*

Active le module `pam_faillock.so` via `authselect enable-feature with-faillock`, puis configure `/etc/security/faillock.conf` :

| Paramètre | Valeur | Signification |
|---|---|---|
| `deny` | 5 | Verrouillage après 5 tentatives échouées |
| `unlock_time` | 900 | Déverrouillage automatique après 15 minutes |

> **FreeIPA :** s'applique aux comptes **locaux** uniquement. Les comptes du domaine utilisent la politique IPA : `ipa pwpolicy-show`.
> Vérifier le profil authselect avant : `authselect current`

---

### Section 25 — PAM pwquality (qualité des mots de passe)
**Règles CIS :** *Minimum Length / Different Characters / Different Categories / Sequential / Dictionary / Enforce for root*

Configure `/etc/security/pwquality.conf` :

| Paramètre | Valeur | Signification |
|---|---|---|
| `minlen` | 14 | Longueur minimale 14 caractères |
| `difok` | 2 | Au moins 2 caractères différents du mot de passe précédent |
| `minclass` | 4 | 4 catégories requises : MAJ + min + chiffres + spéciaux |
| `maxsequence` | 3 | Max 3 caractères séquentiels (ex: `abc`, `123`) |
| `dictcheck` | 1 | Vérification contre le dictionnaire système |
| `enforce_for_root` | — | Applique la politique même pour root |

> **FreeIPA :** s'applique aux comptes locaux. Pour le domaine :
> ```bash
> ipa pwpolicy-mod --minlength=14 --minclasses=4 --maxsequence=3
> ```

---

### Section 26 — Historique des mots de passe (remember=24)
**Règles CIS :** *Limit Password Reuse: password-auth / system-auth*

Configure `pam_pwhistory.so` via `authselect enable-feature with-pwhistory` avec `remember=24`. Empêche la réutilisation des 24 derniers mots de passe.

> **FreeIPA :** pour le domaine : `ipa pwpolicy-mod --history=24`

---

### Section 27 — Politiques d'expiration de compte
**Règles CIS :** *Set Password Maximum Age / Set Account Expiration Following Inactivity / Set Existing Passwords Maximum Age*

| Fichier | Paramètre | Valeur | Effet |
|---|---|---|---|
| `/etc/login.defs` | `PASS_MAX_DAYS` | 365 | Expiration MDP après 1 an (nouveaux comptes) |
| `/etc/default/useradd` | `INACTIVE` | 45 | Désactivation compte 45 jours après expiration MDP |
| `chage` loop | `-M 365` | — | Applique PASS_MAX_DAYS aux comptes existants avec hash |

> **Attention :** la boucle `chage` affecte tous les comptes locaux avec un hash de MDP.
> Vérifier les comptes de service AVANT :
> ```bash
> awk -F: '(/^[^:]+:[^!*]/) {print $1}' /etc/shadow
> ```

---

### Section 28 — Restriction de la commande su (pam_wheel + sugroup)
**Règles CIS :** *Ensure Group Used by pam_wheel Exists and is Empty / Enforce pam_wheel for su*

1. Crée le groupe `sugroup` (vide par défaut)
2. Configure `/etc/pam.d/su` : `auth required pam_wheel.so use_uid group=sugroup`

**Résultat :** la commande `su` est bloquée pour tous les utilisateurs sauf les membres de `sugroup`.

> **Avant d'appliquer** — si certains utilisateurs ont besoin de `su` :
> ```bash
> gpasswd -a <user> sugroup
> ```
> Compatible FreeIPA : les admins utilisent `sudo` via les sudorules IPA, pas `su`.

---

### Section 29 — Journalisation persistante
**Règles CIS :** *Install systemd-journal-remote / journald Storage=persistent*

**Pourquoi Storage=persistent si rsyslog écrit déjà dans /var/log/messages ?**

rsyslog et journald sont complémentaires, pas redondants :

| Capacité | rsyslog seul | + journald persistent |
|---|---|---|
| `/var/log/messages` | ✓ | ✓ |
| `journalctl --boot -1` (boot précédent) | ✗ | ✓ |
| Logs kernel dès le début du boot | partiel | ✓ |
| Analyse forensique post-crash | difficile | ✓ |
| Duplication | — | Non (rsyslog lit via `imjournal`) |

Configure `Storage=persistent` dans `/etc/systemd/journald.conf.d/`.

**systemd-journal-remote** : permet la centralisation des logs journald vers un serveur distant. Optionnel si rsyslog envoie déjà vers un SIEM.

---

## Contexte FreeIPA — points d'attention

Les sections PAM (24, 25, 26, 27, 28) s'appliquent aux **comptes locaux** uniquement. Les comptes FreeIPA sont gérés par SSSD.

| Action FreeIPA équivalente | Commande |
|---|---|
| Politique de lockout | `ipa pwpolicy-mod --maxfail=5 --lockouttime=900` |
| Longueur/complexité MDP | `ipa pwpolicy-mod --minlength=14 --minclasses=4` |
| Historique MDP | `ipa pwpolicy-mod --history=24` |
| Expiration MDP | `ipa pwpolicy-mod --maxlife=365` |
| Voir la politique actuelle | `ipa pwpolicy-show` |

**Vérification authselect obligatoire avant les sections PAM :**
```bash
authselect current
# Le profil doit être : sssd ou ipa
# Sinon : authselect select sssd --force
```

---

## Contexte Satellite — gpgcheck

**`gpgcheck=1` doit être maintenu même avec Red Hat Satellite.**

Satellite gère les repositories et importe les clés GPG, mais `gpgcheck=1` vérifie la signature de chaque package à l'installation — c'est la dernière ligne de défense contre un package corrompu ou compromis. Satellite ne remplace pas cette vérification cryptographique locale.

```bash
# Vérifier la configuration globale
grep gpgcheck /etc/dnf/dnf.conf

# Vérifier tous les repos
grep -r gpgcheck /etc/yum.repos.d/
```

---

## Findings restants après le script

Ces findings CIS Level 1 ne sont **pas couverts** par `cis-harden.sh` et nécessitent une action manuelle ou une décision :

| Finding | Statut | Action requise |
|---|---|---|
| **Set Boot Loader Password in grub2** | ⚠️ Manuel | `grub2-setpassword` — évaluer si pertinent (accès physique protégé ?) |
| **Ensure gpgcheck Enabled for All dnf Package Repositories** | ⚠️ Manuel | Vérifier et corriger tout `gpgcheck=0` dans `/etc/yum.repos.d/` |
| **Enable Kernel Parameter to Log Martian Packets** (`log_martians=1`) | ⚠️ Hors script | Ajouter à la section 6 si souhaité : `sysctl -w net.ipv4.conf.all.log_martians=1` |
| **Enable Kernel Parameter to Ignore Bogus ICMP** (`icmp_ignore_bogus_error_responses=1`) | ⚠️ Hors script | Idem section 6 |
| **Add noexec Option to /tmp** | ⚠️ Manuel | Ajouter `noexec` dans `/etc/fstab` pour `/tmp` (ou section 1 tmpfs) |
| **Disable Network File System (nfs)** | ⚠️ Manuel | `systemctl disable --now nfs-server` si NFS non utilisé |
| **Uninstall net-snmp Package** | ⚠️ Manuel | `dnf remove net-snmp` si SNMP non utilisé |
| **Limit Users' SSH Access** | ⚠️ Manuel | Ajouter `AllowUsers` ou `AllowGroups` dans sshd_config selon politique site |
| **Ensure all users last password change date is in the past** | ⚠️ Manuel | `for u in $(awk -F: '$3>=1000{print $1}' /etc/passwd); do chage -l $u; done` |
| **Ensure that All Entries in The Path of Root Are Directories** | ⚠️ Manuel | `echo $PATH \| tr ':' '\n' \| while read d; do [ -d "$d" ] \|\| echo "INVALIDE: $d"; done` |

---

## Actions manuelles post-exécution

```bash
# 1. Initialiser la base AIDE (fenêtre de maintenance)
/usr/sbin/aide --init
cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 2. Vérifier authselect
authselect current

# 3. Tester connexion SSH + sudo après sections PAM
sudo -l
ssh <user>@localhost

# 4. Valider crypto policy (après reboot)
update-crypto-policies --show
# Attendu : DEFAULT:NO-SHA1:NO-SSHCBC:NO-SSHWEAKCIPHERS:NO-SSHWEAKMACS:NO-WEAKMAC

# 5. Vérifier journald (après reboot)
journalctl --boot -1 | head -5
ls /var/log/journal/

# 6. Aligner politique FreeIPA
ipa pwpolicy-show
ipa pwpolicy-mod --minlength=14 --minclasses=4 --history=24 \
    --maxlife=365 --lockouttime=900 --maxfail=5

# 7. Ajouter membres sugroup si besoin
gpasswd -a <user> sugroup

# 8. Relancer le scan OpenSCAP pour confirmer
oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis \
    --results scan-post-patch.xml \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

---

## Contenu du dépôt

| Fichier | Description |
|---|---|
| `cis-harden.sh` | Script principal (29 sections, `--help`, `--dry-run`, `--section`) |
| `README.md` | Ce document |
