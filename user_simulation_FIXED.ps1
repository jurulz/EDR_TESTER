# ============================================================
#  USER ENVIRONMENT SIMULATION v2.0
#  Simule un vrai poste d'usager avec donnees sensibles fictives
#  NAS, cartes de credit, mots de passe, cles AWS, tokens, etc.
#  Usage: powershell -ep bypass -File user_simulation.ps1
#  AVERTISSEMENT: Donnees entierement fictives -- usage lab seulement
# ============================================================

$global:SimYear = (Get-Date).Year
$global:SimLog  = @()

function Write-Phase {
    param([string]$N, [string]$T)
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor DarkCyan
    Write-Host "  [$N] $T" -ForegroundColor Cyan
    Write-Host "  =============================================" -ForegroundColor DarkCyan
}
function Write-OK   { param([string]$T) Write-Host "    [+] $T" -ForegroundColor Green  ; $global:SimLog += "[OK]  $T" }
function Write-Fail { param([string]$T) Write-Host "    [-] $T" -ForegroundColor Red    ; $global:SimLog += "[ERR] $T" }
function Write-Info { param([string]$T) Write-Host "    [*] $T" -ForegroundColor Gray   }
function New-File   {
    param([string]$Path, [string]$Content)
    Try {
        $dir = Split-Path $Path
        if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Set-Content -Path $Path -Value $Content -Encoding UTF8 -Force
        Write-OK "$(Split-Path $Path -Leaf)"
    } Catch { Write-Fail "$(Split-Path $Path -Leaf): $($_.Exception.Message)" }
}

# ============================================================
#  GENERATEURS DE DONNEES FICTIVES
# ============================================================

function New-FakeCC {
    # Cartes de credit fictives (format valide mais inutilisables)
    $prefixes = @("4532","4716","5425","5234","371449","6011")
    $prefix = $prefixes | Get-Random
    $remaining = 16 - $prefix.Length
    $num = $prefix + (-join ((0..9) | Get-Random -Count $remaining))
    $exp = "$(Get-Random -Min 1 -Max 12)/$(Get-Random -Min 26 -Max 29)"
    $cvv = Get-Random -Min 100 -Max 999
    $types = @{
        "4" = "Visa"
        "5" = "Mastercard"
        "3" = "Amex"
        "6" = "Discover"
    }
    $type = $types[($prefix[0]).ToString()]
    return "$type $($num -replace '(\d{4})','$1 ') | Exp: $exp | CVV: $cvv"
}

function New-FakeNAS {
    # NAS (Numero d'Assurance Sociale) fictif format canadien
    # Commence par 9 = fictif/temporaire selon les regles CRA
    $block1 = "9$(Get-Random -Min 10 -Max 99)"
    $block2 = Get-Random -Min 100 -Max 999
    $block3 = Get-Random -Min 100 -Max 999
    return "$block1 $block2 $block3"
}

function New-FakeAWSKey {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $keyId = "AKIA" + (-join ((1..16) | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] }))
    $secretChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    $secret = -join ((1..40) | ForEach-Object { $secretChars[(Get-Random -Max $secretChars.Length)] })
    return @{ KeyId = $keyId; Secret = $secret }
}

function New-FakeAzureKey {
    $guid = [System.Guid]::NewGuid().ToString()
    $tenant = [System.Guid]::NewGuid().ToString()
    $secret = -join ((1..32) | ForEach-Object { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[(Get-Random -Max 62)] }) + "=="
    return @{ TenantId = $tenant; ClientId = $guid; Secret = $secret }
}

function New-FakeIBAN {
    $bank = @("CA","GB","FR","DE","CH") | Get-Random
    $num = -join ((1..20) | ForEach-Object { Get-Random -Min 0 -Max 9 })
    return "${bank}$(Get-Random -Min 10 -Max 99)${num}"
}

function New-FakeSSHKey {
    $keyChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    $key = -join ((1..342) | ForEach-Object { $keyChars[(Get-Random -Max $keyChars.Length)] })
    return "-----BEGIN RSA PRIVATE KEY-----`n$($key -replace '(.{64})','$1`n')`n-----END RSA PRIVATE KEY-----"
}

function New-FakeToken {
    param([string]$Type = "bearer")
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $token = -join ((1..64) | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
    return "${Type}_${token}"
}

function New-FakePassword {
    param([string]$Prefix = "Corp")
    $specials = @("!","@","#","$","&","*")
    $sp = $specials | Get-Random
    return "${Prefix}${global:SimYear}${sp}$(Get-Random -Min 10 -Max 99)"
}

# ============================================================
#  SELECTION DU PROFIL
# ============================================================

Clear-Host
Write-Host ""
Write-Host "  +=============================================+" -ForegroundColor Cyan
Write-Host "  |   USER ENVIRONMENT SIMULATION  v2.0        |" -ForegroundColor Cyan
Write-Host "  |   Donnees sensibles fictives -- Lab only    |" -ForegroundColor DarkCyan
Write-Host "  +=============================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Choisir un profil d'usager:" -ForegroundColor White
Write-Host "  [1] Analyste Financiere / Comptabilite" -ForegroundColor White
Write-Host "  [2] Directeur Ressources Humaines" -ForegroundColor White
Write-Host "  [3] Architecte IT / Securite" -ForegroundColor White
Write-Host "  [4] Directrice Ventes / Commercial" -ForegroundColor White
Write-Host "  [5] PDG / Direction" -ForegroundColor White
Write-Host "  [6] Profil aleatoire" -ForegroundColor White
Write-Host ""
Write-Host "  Choix [1-6]: " -NoNewline -ForegroundColor Cyan
$choice = Read-Host

$profiles = @{
    "1" = @{ Name="Marie Tremblay";       Title="Analyste Financiere Senior";  Co="Groupe Financier Horizon"; Email="marie.tremblay@horizonfinancier.com";   Dept="Comptabilite"; Phone="514-555-0142"; Folder="Comptabilite" }
    "2" = @{ Name="Jean-Philippe Gagnon"; Title="Directeur RH";                Co="Solutions RH Plus";        Email="jp.gagnon@rhplus.ca";                  Dept="RH";           Phone="438-555-0287"; Folder="RessourcesHumaines" }
    "3" = @{ Name="Alexandre Bergeron";   Title="Architecte Solutions Senior"; Co="TechCorp Canada";          Email="a.bergeron@techcorp.ca";               Dept="IT-Securite";  Phone="450-555-0391"; Folder="IT_Infrastructure" }
    "4" = @{ Name="Sophie Lavoie";        Title="Directrice Ventes Quebec";    Co="Ventes Pro Inc";           Email="s.lavoie@ventespro.ca";                Dept="Ventes";       Phone="581-555-0456"; Folder="Ventes" }
    "5" = @{ Name="Robert Charlebois";    Title="President Directeur General"; Co="Groupe Charlebois Inc";    Email="r.charlebois@groupecharlebois.com";    Dept="Direction";    Phone="514-555-0001"; Folder="Direction_Confidentiel" }
}

if ($choice -eq "6" -or -not $profiles.ContainsKey($choice)) { $choice = (1..5 | Get-Random).ToString() }

$P       = $profiles[$choice]
$year    = $global:SimYear
$base    = $env:USERPROFILE
$docDir  = "$base\Documents\$($P.Folder)"
$firstName = $P.Name.Split(" ")[0]
$lastName  = $P.Name.Split(" ")[1]
$domain    = $P.Co.ToLower() -replace "[^a-z0-9]",""

# Generer les donnees sensibles fictives
$cc1     = New-FakeCC
$cc2     = New-FakeCC
$cc3     = New-FakeCC
$nas1    = New-FakeNAS
$nas2    = New-FakeNAS
$aws1    = New-FakeAWSKey
$aws2    = New-FakeAWSKey
$azure1  = New-FakeAzureKey
$iban1   = New-FakeIBAN
$sshKey  = New-FakeSSHKey
$tok1    = New-FakeToken "ghp"
$tok2    = New-FakeToken "xoxb"
$tok3    = New-FakeToken "sk"
$pw1     = New-FakePassword "Corp"
$pw2     = New-FakePassword "Admin"
$pw3     = New-FakePassword "DB"
$pw4     = New-FakePassword "VPN"
$pw5     = New-FakePassword "Azure"

Write-Host ""
Write-Host "  Profil : $($P.Name) -- $($P.Title)" -ForegroundColor Yellow
Write-Host "  Dossier: $docDir" -ForegroundColor Gray
Write-Host ""

# ============================================================
#  PHASE 1 -- STRUCTURE DE DOSSIERS
# ============================================================
Write-Phase "1/9" "Structure de dossiers"

$dirs = @(
    "$docDir\$year", "$docDir\Archives", "$docDir\Confidentiel",
    "$base\Documents\Projets", "$base\Documents\Personnel",
    "$base\Documents\Reunions", "$base\Documents\Formations",
    "$base\Downloads\Logiciels", "$base\Downloads\Documents_Recus",
    "$base\Desktop\Travail_en_cours",
    "$base\Documents\Credentials_Backup"
)
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
Write-OK "$($dirs.Count) dossiers crees"

# ============================================================
#  PHASE 2 -- FICHIER CREDENTIALS PRINCIPAL (cible prioritaire)
# ============================================================
Write-Phase "2/9" "Fichier credentials & donnees sensibles"

New-File "$docDir\Confidentiel\CREDENTIALS_ACCES_SYSTEMES.txt" @"
================================================================
  ACCES SYSTEMES -- ULTRA CONFIDENTIEL
  $($P.Name) | $($P.Title)
  $($P.Co)
  Derniere mise a jour: $(Get-Date -Format 'yyyy-MM-dd')
  NE PAS PARTAGER -- NE PAS ENVOYER PAR EMAIL
================================================================

== IDENTIFIANTS RESEAU ==
Domaine    : CORP\$($P.Email.Split('@')[0])
Mot passe  : $pw1
MFA backup : 847291 / 334817 / 992044

== APPLICATIONS INTERNES ==
ERP (SAP)        : $($P.Email.Split('@')[0]) / $pw2
CRM (Salesforce) : $($P.Email) / $pw3
Jira             : $($P.Email.Split('@')[0]) / $pw1
SharePoint       : Authentification Windows integree
ServiceNow       : sn_$($P.Email.Split('@')[0]) / Snow${year}!

== ACCES BANCAIRES ==
Banque principale  : TD Bank Business
  No. compte       : 8834-229-10044
  No. transit      : 00482-004
  Mot passe web    : TDCorp${year}Secure!
  Token materiel   : Utiliser fob #4821

Compte secondaire  : Desjardins
  No. compte       : 9922-441-08823
  IBAN             : $iban1
  NIP telephone    : 4892

== CLOUD & INFRASTRUCTURE ==
AWS Account ID    : 829441028834
  Access Key ID   : $($aws1.KeyId)
  Secret Key      : $($aws1.Secret)
  Region          : ca-central-1
  Console URL     : https://console.aws.amazon.com
  Root email      : aws-root@${domain}.com
  Root password   : $pw2

Azure AD
  Tenant ID       : $($azure1.TenantId)
  Client ID       : $($azure1.ClientId)
  Client Secret   : $($azure1.Secret)
  Subscription    : corp-prod-001

GitHub
  Token PAT       : $tok1
  Org             : $domain-corp

Slack (admin)
  Token           : $tok2

OpenAI API
  Key             : $tok3-$(New-FakeToken 'live')

== VPN & ACCES DISTANT ==
VPN Endpoint      : vpn.${domain}.ca:443
  Username        : $($P.Email.Split('@')[0])
  Mot passe       : $pw4
  Certificat      : corp-cert-2024.p12
  Phrase passe    : CertPhrase${year}!

RDP Serveur admin : 192.168.1.10:3389
  Username        : CORP\svc_rdp_admin
  Mot passe       : $pw2

== BASES DE DONNEES ==
SQL Server prod   : SRV-SQL01.corp.local,1433
  Login           : sa
  Mot passe       : $pw3
  DB principale   : PROD_MAIN_DB

PostgreSQL        : db-pg01.corp.local:5432
  Login           : pgadmin
  Mot passe       : PG${year}Admin!

MongoDB           : mongodb://mongo01.corp.local:27017
  Login           : mongoadmin
  Mot passe       : Mongo${year}#Secure

== NAS (NUMEROS D'ASSURANCE SOCIALE) EMPLOYES ==
NOTE: Fichier consolide pour dossiers paie
$($P.Name)        : $nas1
Pierre Marleau    : $(New-FakeNAS)
Lucie Fontaine    : $(New-FakeNAS)
Marc Vezina       : $(New-FakeNAS)
Anne Beausoleil   : $(New-FakeNAS)
France Ouellet    : $nas2

================================================================
  CONSERVE DANS COFFRE-FORT PHYSIQUE -- Copie numerique temporaire
================================================================
"@

# Fichier SSH Keys
New-File "$docDir\Confidentiel\SSH_KEYS_SERVEURS.txt" @"
SSH KEYS -- ACCES SERVEURS PRODUCTION
$($P.Co) | IT Infrastructure
CONFIDENTIEL -- IT Seulement

== CLE PRIVEE RSA -- SRV-PROD-01 ==
Host: srv-prod-01.corp.local
User: deploy_user
$sshKey

== CLE PRIVEE ED25519 -- AWS EC2 ==
Host: ec2-54-123-45-67.ca-central-1.compute.amazonaws.com
User: ubuntu
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB$((-join ((1..200) | ForEach-Object { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(Get-Random -Max 64)] }))=
-----END OPENSSH PRIVATE KEY-----

PASSPHRASE: SSHProd${year}Key!
"@

Write-OK "Credentials systemes generes (fictifs)"

# ============================================================
#  PHASE 3 -- CARTES DE CREDIT & FINANCES
# ============================================================
Write-Phase "3/9" "Donnees financieres & cartes de credit"

New-File "$docDir\Confidentiel\CARTES_CREDIT_ENTREPRISE.txt" @"
REGISTRE CARTES DE CREDIT -- $($P.Co)
CONFIDENTIEL -- Finance seulement
Mis a jour: $(Get-Date -Format 'yyyy-MM-dd')

================================================================
CARTE CORPORATIVE PRINCIPALE
$cc1
Titulaire   : $($P.Name)
Limite      : 25,000$
Solde actuel: 8,492.33$
Usage       : Depenses operationnelles
Code auth   : CORP-AUTH-7734

CARTE VOYAGE DIRECTION
$cc2
Titulaire   : Direction Generale
Limite      : 50,000$
Solde actuel: 2,114.50$
Usage       : Voyages et representation
Code auth   : CORP-VIP-2291

CARTE ACHAT INFORMATIQUE
$cc3
Titulaire   : Service IT
Limite      : 15,000$
Solde actuel: 3,887.22$
Usage       : Achats IT et licences
Code auth   : IT-PURCH-5541
================================================================

NUMEROS COMPTE ENTREPRISE (facturation)
Compte principal  : $(Get-Random -Min 1000 -Max 9999)-$(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Transit           : 0$(Get-Random -Min 100 -Max 999)-00$(Get-Random -Min 1 -Max 9)
Institution       : $(Get-Random -Min 1 -Max 9)
IBAN international: $iban1

COORDONNEES BANCAIRES VIREMENT
Banque    : TD Bank Canada Trust
Adresse   : 150 King St W, Toronto ON M5H 1J9
Swift/BIC : TDOMCATTTOR
"@

New-File "$base\Documents\Personnel\Finances_Personnelles_Privees.txt" @"
FINANCES PERSONNELLES -- PRIVE
$($P.Name) | $(Get-Date -Format 'yyyy-MM-dd')
NE PAS LAISSER ACCESSIBLE

CARTES PERSONNELLES
Carte principale  : $cc1
Carte secours     : $cc2
Debit Desjardins  : $(Get-Random -Min 1000 -Max 9999) $(Get-Random -Min 1000 -Max 9999) $(Get-Random -Min 1000 -Max 9999) $(Get-Random -Min 1000 -Max 9999)
NIP Debit         : $(Get-Random -Min 1000 -Max 9999)

INFO PERSONNELLES
NAS               : $nas1
Date naissance    : $(Get-Random -Min 1970 -Max 1990)-$('{0:D2}' -f (Get-Random -Min 1 -Max 12))-$('{0:D2}' -f (Get-Random -Min 1 -Max 28))
No. Passeport     : AB$(Get-Random -Min 100000 -Max 999999)
Permis conduire   : $((-join ((1..5) | ForEach-Object { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(Get-Random -Max 26)] })))$(Get-Random -Min 100000 -Max 999999)

COMPTES EN LIGNE PERSONNELS
Netflix           : $($P.Email) / Netflix${year}!
Amazon            : $($P.Email) / Amazon#$year
Banque perso      : $($P.Email.Split('@')[0]) / BanquePerso${year}Secure
"@

Write-OK "Donnees financieres & cartes fictives creees"

# ============================================================
#  PHASE 4 -- DOCUMENTS METIER SELON PROFIL
# ============================================================
Write-Phase "4/9" "Documents metier confidentiels ($($P.Dept))"

switch ($choice) {
    "1" { # Finance
        New-File "$docDir\$year\Budget_Previsionnel_$year.txt" @"
BUDGET PREVISIONNEL $year -- CONFIDENTIEL
$($P.Co) | $($P.Dept)
Prepare par: $($P.Name)

REVENUS PROJETES
Ventes produits   : 4,250,000$
Services          : 1,890,000$
Licences          : 540,000$
Total revenus     : 6,680,000$

DEPENSES OPERATIONNELLES
Masse salariale   : 2,840,000$
Infrastructure IT : 425,000$
Marketing         : 380,000$
R&D               : 290,000$
Loyers            : 180,000$
Divers            : 145,000$
Total depenses    : 4,260,000$

EBITDA PROJETE    : 2,420,000$ (36.2%)
Amortissements    : 180,000$
EBIT              : 2,240,000$
Impots (26.5%)    : 593,600$
BENEFICE NET      : 1,646,400$

NOTE: Document pre-conseil d'administration -- NE PAS DIFFUSER
"@
        New-File "$docDir\Confidentiel\Paie_Registre_Confidentiel.txt" @"
REGISTRE DE PAIE -- ULTRA CONFIDENTIEL
$($P.Co) | $($P.Dept) | $year

Nom                     | Poste                    | NAS         | Salaire   | Bonus
$($P.Name)              | $($P.Title)              | $nas1       | 98,500$   | 12,000$
Pierre Marleau          | Analyste Sr              | $(New-FakeNAS) | 74,000$ | 6,000$
Lucie Fontaine          | Comptable CPA            | $(New-FakeNAS) | 71,500$ | 5,000$
Marc Vezina             | Controleur               | $(New-FakeNAS) | 89,000$ | 9,500$
Anne Beausoleil         | Coordonnatrice           | $(New-FakeNAS) | 58,000$ | 3,000$
Robert Chen             | Analyste BI              | $(New-FakeNAS) | 68,000$ | 5,500$

TOTAL MASSE SALARIALE: 459,000$
AVANTAGES SOCIAUX (18%): 82,620$
COUT TOTAL EMPLOYES: 541,620$

CODES ACCES PAIE
ADP Workforce: paie_$($P.Email.Split('@')[0]) / $pw3
Desjardins paie: $(Get-Random -Min 10000 -Max 99999) / DP${year}Paie!
"@
    }
    "2" { # RH
        New-File "$docDir\Confidentiel\Dossiers_Employes_Complets.txt" @"
DOSSIERS EMPLOYES -- RESSOURCES HUMAINES CONFIDENTIEL
$($P.Co) | Mis a jour: $(Get-Date -Format 'yyyy-MM-dd')

=== EMPLOYE #001 ===
Nom              : Pierre Marleau
NAS              : $(New-FakeNAS)
Date naissance   : 1985-07-22
Adresse          : 4521 Rue Saint-Denis, Montreal QC H2J 2L3
Tel personnel    : 514-888-$(Get-Random -Min 1000 -Max 9999)
Email perso      : p.marleau.perso@gmail.com
Salaire          : 74,000$ | Compte paie: $(Get-Random -Min 1000 -Max 9999)-$(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Evaluation       : 4.2/5 | Statut: Eligible promotion

=== EMPLOYE #002 ===
Nom              : Lucie Fontaine
NAS              : $(New-FakeNAS)
Date naissance   : 1990-03-14
Adresse          : 892 Boul. Saint-Laurent, Laval QC H7N 2K4
Tel personnel    : 450-777-$(Get-Random -Min 1000 -Max 9999)
Email perso      : lucie.fontaine@hotmail.ca
Salaire          : 71,500$ | Compte paie: $(Get-Random -Min 1000 -Max 9999)-$(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Evaluation       : 3.8/5 | Statut: Satisfaisant

=== EMPLOYE #003 === DOSSIER DISCIPLINE
Nom              : Marc Vezina
NAS              : $(New-FakeNAS)
Avertissement    : 1er avertissement ecrit (2024-08-15)
Motif            : Absenteisme excessif (12 jours YTD)
Plan amelioration: Actif jusqu'au $(((Get-Date).AddMonths(3)).ToString('yyyy-MM-dd'))
"@
    }
    "3" { # IT
        New-File "$docDir\Confidentiel\INFRASTRUCTURE_SECRETS.txt" @"
SECRETS INFRASTRUCTURE -- IT SECURITE CONFIDENTIEL
$($P.Co) | $($P.Title)
ACCES RESTREINT -- EQUIPE IT SEULEMENT

== ACTIVE DIRECTORY ==
Domain Admin     : CORP\Administrator
Password         : $pw2
Password backup  : $pw1

Service Accounts:
  svc_backup     : SVC${year}Backup!
  svc_sql        : $pw3
  svc_exchange   : Exchange${year}Srv!
  svc_vmware     : VMware${year}$!

== CERTIFICATS & CLES ==
Wildcard SSL     : *.${domain}.ca
  Expire         : $(((Get-Date).AddYears(2)).ToString('yyyy-MM-dd'))
  Password PFX   : CertPFX${year}!

Code Signing     : $($P.Co) Code Sign
  Password       : CodeSign${year}Secure

== TOKENS & SECRETS CLOUD ==
AWS Production:
  Account        : 829441028834
  Access Key     : $($aws1.KeyId)
  Secret         : $($aws1.Secret)
  S3 Bucket      : corp-prod-backup-8834

AWS Development:
  Account        : 448821039921
  Access Key     : $($aws2.KeyId)
  Secret         : $($aws2.Secret)

GitHub Actions Secret:
  GITHUB_TOKEN   : $tok1
  DEPLOY_KEY     : $(New-FakeToken 'dk')

Terraform State:
  Backend S3     : tf-state-${domain}-prod
  Lock DynamoDB  : tf-lock-${domain}
  Encryption Key : TF${year}StateKey!

Kubernetes:
  Cluster        : k8s.${domain}.ca
  Service Account: $(New-FakeToken 'k8s')
"@
        New-File "$docDir\Confidentiel\Vulnerabilites_Critiques.txt" @"
RAPPORT VULNERABILITES -- CONFIDENTIEL
Scanner: Nessus + Qualys | Date: $(Get-Date -Format 'yyyy-MM-dd')

CRITIQUE (CVSS >= 9.0) -- ACTION IMMEDIATE REQUISE
CVE-2024-1234  SRV-WEB02     Apache 2.4.49 RCE          CVSS: 9.8
CVE-2023-44487 SRV-API01     HTTP/2 Rapid Reset          CVSS: 9.4
CVE-2024-5678  SRV-SQL01     SQL Injection non patche    CVSS: 9.1

ELEVE (CVSS 7-8.9)
CVE-2024-2345  14 postes     Windows Print Spooler       CVSS: 8.8
CVE-2023-3456  SRV-DC01      Kerberos delegation         CVSS: 8.1
               Compte: svc_sql mot passe : $pw3

ACCES RDP EXPOSE INTERNET
IP externe     : 67.43.$(Get-Random -Min 100 -Max 255).$(Get-Random -Min 1 -Max 254):3389
Compte expose  : CORP\administrator
Password       : $pw2  <<< CHANGER IMMEDIATEMENT

STATUS: En remediation -- deadline $(((Get-Date).AddDays(30)).ToString('yyyy-MM-dd'))
"@
    }
    "4" { # Ventes
        New-File "$docDir\Confidentiel\Pipeline_Clients_Confidentiel.txt" @"
PIPELINE VENTES CONFIDENTIEL -- $year
$($P.Co) | $($P.Title)
NE PAS PARTAGER HORS EQUIPE DIRECTION

OPPORTUNITES PRIORITAIRES
Acmecorp (MTL)   : 850,000$ | 85% | Fermeture: ce mois | Contact: pdupont@acme.com / AcmePass${year}!
GlobalTech (TOR) : 2,100,000$ | 60% | Fermeture: Q3 | Contact: sjohnson@globaltech.ca
PetroQC (QC)     : 430,000$ | 90% | Fermeture: 2 sem | Contact: fmorin@petroqc.com
BancaVie (LAV)   : 1,800,000$ | 35% | Fermeture: Q4

INFORMATIONS CONCURRENTES (CONFIDENTIEL)
VenteMax Inc     : Prix +23% vs nous | Losing GlobalTech
SolutionsPro     : Faiblesse: support apres-vente
Strategie        : Attaquer sur TCO 3 ans + support 24/7

COMMISSIONS PREVUES $year
$($P.Name)       : 89,400$ (base 3% sur 2.98M$)
Marc Beaudoin    : 44,700$
Isabelle Roy     : 156,000$

ACCES CRM
Salesforce admin : $($P.Email) / SF${year}Admin!
HubSpot          : $($P.Email.Split('@')[0]) / HB${year}Corp!
"@
    }
    "5" { # PDG
        New-File "$docDir\Confidentiel\ACQUISITION_CONFIDENTIEL_NDA.txt" @"
PROJET PHOENIX -- ACQUISITION CONFIDENTIELLE
$($P.Co) | $($P.Title)
NDA SIGNE -- DISTRIBUTION RESTREINTE AU COMITE RESTREINT UNIQUEMENT

CIBLE D'ACQUISITION: CompetitorCo Inc
Valorisation      : 12,500,000$
Due diligence     : 85% completee
Signature prevue  : $(((Get-Date).AddDays(45)).ToString('yyyy-MM-dd'))
Financement       : Credit syndique + fonds propres
  Banque lead     : RBC Capital Markets
  Reference dossier: RBC-2024-PHXQ-8834
  Contact banquier : john.doe@rbccm.com / 416-555-0100

DONNEES FINANCIERES CIBLE (NDA)
EBITDA 2023       : 1,840,000$
Multiple retenu   : 6.8x EBITDA
Prix offre        : 12,512,000$
Conditions        : Earn-out 18 mois sur performance

INFORMATIONS PDG CIBLE
Nom              : Marc-Andre Dupont
NAS              : $(New-FakeNAS)
Email perso      : m.dupont.perso@gmail.com
Tel cell         : 514-$(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)

CODE ACCES DATA ROOM
URL              : https://dataroom.deloitte.com/phoenix
Login            : $($P.Email)
Password         : DataRoom${year}NDA!
Code 2FA backup  : 882934 | 774421 | 993017

COMPTE SEQUESTRE (CLOSING)
Notaire          : Me. Sylvie Blanchard, Lavery Avocats
No. compte       : $(Get-Random -Min 10000000 -Max 99999999)
Montant sequestre: 1,250,000$
"@
    }
}

# ============================================================
#  PHASE 5 -- FICHIERS AWS/CLOUD CONFIG
# ============================================================
Write-Phase "5/9" "Fichiers de configuration cloud & secrets"

New-File "$base\Documents\Credentials_Backup\.aws_credentials.txt" @"
[default]
aws_access_key_id     = $($aws1.KeyId)
aws_secret_access_key = $($aws1.Secret)
region                = ca-central-1
output                = json

[development]
aws_access_key_id     = $($aws2.KeyId)
aws_secret_access_key = $($aws2.Secret)
region                = us-east-1

[production-readonly]
aws_access_key_id     = $(New-FakeAWSKey).KeyId
aws_secret_access_key = $(New-FakeAWSKey).Secret
role_arn              = arn:aws:iam::829441028834:role/ReadOnly
"@

New-File "$base\Documents\Credentials_Backup\.env_production.txt" @"
# FICHIER .ENV PRODUCTION -- NE PAS COMMITTER
# Copie locale backup -- $($P.Co)

DATABASE_URL=postgresql://pgadmin:$pw3@db-pg01.corp.local:5432/PROD_MAIN_DB
REDIS_URL=redis://:Redis${year}Pass!@redis01.corp.local:6379/0

AWS_ACCESS_KEY_ID=$($aws1.KeyId)
AWS_SECRET_ACCESS_KEY=$($aws1.Secret)
AWS_REGION=ca-central-1
S3_BUCKET=corp-prod-files-8834

AZURE_TENANT_ID=$($azure1.TenantId)
AZURE_CLIENT_ID=$($azure1.ClientId)
AZURE_CLIENT_SECRET=$($azure1.Secret)

GITHUB_TOKEN=$tok1
SLACK_BOT_TOKEN=$tok2
OPENAI_API_KEY=$tok3-$(New-FakeToken 'live')

JWT_SECRET=$(New-FakeToken 'jwt')
ENCRYPTION_KEY=$(New-FakeToken 'enc')
SESSION_SECRET=$(New-FakeToken 'sess')

SMTP_HOST=mail.corp.local
SMTP_USER=no-reply@${domain}.ca
SMTP_PASS=SMTP${year}Mail!

STRIPE_SECRET_KEY=sk_live_$(New-FakeToken 'stripe')
STRIPE_WEBHOOK_SECRET=whsec_$(New-FakeToken 'wh')

ADMIN_EMAIL=$($P.Email)
ADMIN_PASSWORD=$pw2
"@

New-File "$base\Documents\Credentials_Backup\terraform.tfvars.txt" @"
# Terraform Variables -- CONFIDENTIEL
# $($P.Co) | Infrastructure as Code

aws_access_key    = "$($aws1.KeyId)"
aws_secret_key    = "$($aws1.Secret)"
aws_region        = "ca-central-1"

db_password       = "$pw3"
admin_password    = "$pw2"
vpn_shared_secret = "VPN$(New-FakeToken 'ipsec')"

azure_tenant_id   = "$($azure1.TenantId)"
azure_client_id   = "$($azure1.ClientId)"
azure_client_secret = "$($azure1.Secret)"

cloudflare_api_token = "$(New-FakeToken 'cf')"
datadog_api_key      = "$(New-FakeToken 'dd')"
pagerduty_key        = "$(New-FakeToken 'pd')"
"@

Write-OK "Fichiers cloud/infra crees"

# ============================================================
#  PHASE 6 -- EMAILS SIMULES AVEC DONNEES SENSIBLES
# ============================================================
Write-Phase "6/9" "Emails simules avec donnees sensibles"

New-File "$base\Documents\Reunions\email_MDPtemporaire_IT.txt" @"
DE: it-support@${domain}.ca
A: $($P.Email)
DATE: $(Get-Date -Format 'ddd dd MMM yyyy HH:mm')
OBJET: [IT Support] Reinitialisation compte -- Acces temporaire

Bonjour $firstName,

Suite a votre demande de reinitialisation, voici vos nouveaux acces:

  Username : CORP\$($P.Email.Split('@')[0])
  Password : $pw1
  VPN      : $pw4

Vous devrez changer ces mots de passe a la premiere connexion.
Lien portail: https://portal.${domain}.ca

Ce message contient des informations confidentielles.
Support IT | Tel: 514-555-0100
"@

New-File "$base\Documents\Reunions\email_virement_bancaire.txt" @"
DE: finances@${domain}.ca
A: $($P.Email)
DATE: $(Get-Date -Format 'ddd dd MMM yyyy HH:mm')
OBJET: CONFIDENTIEL - Virement urgent client

$firstName,

Virement a effectuer AUJOURD'HUI avant 15h:

  Beneficiaire : Fournisseur ABC Inc
  IBAN         : $iban1
  Montant      : 48,500.00 CAD
  Reference    : INV-$(Get-Random -Min 10000 -Max 99999)
  Code autorisation: VIRT-$(Get-Random -Min 1000 -Max 9999)-$(Get-Date -Format 'ddMM')

Code confirmation banque: $(Get-Random -Min 100000 -Max 999999)
NIP telephone: $(Get-Random -Min 1000 -Max 9999)

Confirmer execution par retour de courriel.
$($P.Co) | Direction Finances
"@

New-File "$base\Documents\Reunions\email_AWS_facture.txt" @"
DE: billing@amazon.com
A: aws-root@${domain}.com
DATE: $(Get-Date -Format 'ddd dd MMM yyyy HH:mm')
OBJET: AWS Invoice - $(Get-Date -Format 'MMMM yyyy') - Account 829441028834

AWS Account: 829441028834
Periode    : $(Get-Date -Format 'MMMM yyyy')
Montant    : 4,892.33 USD

Services:
  EC2 Instances (prod): 1,840.00$
  RDS Multi-AZ        : 1,230.00$
  S3 Storage + Transfer: 420.00$
  CloudFront CDN      : 289.00$
  Misc                : 1,113.33$

Carte de debit: $cc1
"@

Write-OK "Emails simules crees"

# ============================================================
#  PHASE 7 -- FICHIERS BUREAU (travail en cours)
# ============================================================
Write-Phase "7/9" "Fichiers bureau -- travail en cours"

New-File "$base\Desktop\TODO_$(Get-Date -Format 'ddMMyyyy').txt" @"
TACHES DU JOUR -- $(Get-Date -Format 'dddd dd MMMM yyyy')
$firstName $lastName | $($P.Title)

[X] Revue emails matinaux
[X] Reunion standup equipe 9h00
[ ] Finaliser rapport pour direction (deadline auj. 17h)
[ ] Approuver virement fournisseur (voir email Finance)
[ ] Appel $firstName Chen 14h30 -- renouvellement contrat
[ ] Soumettre notes de frais ($($cc1.Split('|')[0].Trim()))
[ ] Revoir proposition acquisition (voir dossier Phoenix)
[ ] MDP AWS a changer (rappel IT)

RAPPELS
- Reunion conseil d'admin: $(((Get-Date).AddDays(7)).ToString('dd/MM/yyyy')) 9h00
- Evaluation performance Q3: soumettre avant $(((Get-Date).AddDays(14)).ToString('dd/MM/yyyy'))
- Renouvellement assurance: $(((Get-Date).AddMonths(2)).ToString('MM/yyyy'))

NOTE PERSO: MDP wifi maison = Famille${year}Wifi! | Alarme: $(Get-Random -Min 1000 -Max 9999)
"@

New-File "$base\Desktop\Travail_en_cours\Draft_Rapport_Direction.txt" @"
BROUILLON -- NE PAS ENVOYER
Rapport trimestriel pour $($P.Co)
Auteur: $($P.Name) | $(Get-Date -Format 'yyyy-MM-dd')

POINTS CLES
1. Performance vs objectifs: 94% (en dessous de 100% cible)
2. Incidents securite: 2 (voir rapport IT confidentiel)
3. Budget restant Q$(if((Get-Date).Month -le 3){1} elseif((Get-Date).Month -le 6){2} elseif((Get-Date).Month -le 9){3} else {4}): 145,000$

NOTE CONFIDENTIELLE (ne pas inclure version finale):
   - Marc Vezina: performance insuffisante, potentiel depart Q1 $(($year+1))
   - Acquisition CompetitorCo: annonce prevue $(((Get-Date).AddMonths(2)).ToString('MMMM yyyy'))
   - Budget IT: 200,000$ non depense -- potentiel retour direction

MOT DE PASSE RAPPORT FINAL: Rapport${year}Dir!
"@

Write-OK "Fichiers bureau crees"

# ============================================================
#  PHASE 8 -- HISTORIQUE & RECENT DOCS
# ============================================================
Write-Phase "8/9" "Simulation historique Recent Documents"

Try {
    $shell = New-Object -ComObject WScript.Shell
    $recentFiles = @(
        "$docDir\Confidentiel\CREDENTIALS_ACCES_SYSTEMES.txt",
        "$docDir\Confidentiel\CARTES_CREDIT_ENTREPRISE.txt",
        "$base\Desktop\TODO_$(Get-Date -Format 'ddMMyyyy').txt"
    )
    foreach ($rf in $recentFiles) {
        if (Test-Path $rf) {
            $lnk = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Recent\$(Split-Path $rf -Leaf).lnk")
            $lnk.TargetPath = $rf
            $lnk.Save()
        }
    }
    Write-OK "Recent Documents simules ($($recentFiles.Count) raccourcis)"
} Catch { Write-Fail "Recent Docs: $($_.Exception.Message)" }

# ============================================================
#  PHASE 9 -- RAPPORT FINAL
# ============================================================
Write-Phase "9/9" "Rapport de simulation"

$allFiles = Get-ChildItem $base\Documents -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
$totalSize = ($allFiles | Measure-Object -Property Length -Sum).Sum

Write-Host ""
Write-Host "  +================================================+" -ForegroundColor Green
Write-Host "  |  SIMULATION COMPLETE                           |" -ForegroundColor Green
Write-Host "  +================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Profil    : $($P.Name)" -ForegroundColor Yellow
Write-Host "  Titre     : $($P.Title)" -ForegroundColor White
Write-Host "  Societe   : $($P.Co)" -ForegroundColor White
Write-Host "  Email     : $($P.Email)" -ForegroundColor White
Write-Host ""
Write-Host "  Donnees sensibles fictives incluses:" -ForegroundColor Cyan
Write-Host "    NAS (x5+)          : Format 9XX XXX XXX (fictif)" -ForegroundColor White
Write-Host "    Cartes credit (x3) : Visa/MC/Amex (non fonctionnelles)" -ForegroundColor White
Write-Host "    Cles AWS (x2)      : $($aws1.KeyId)" -ForegroundColor Yellow
Write-Host "    Secrets Azure      : Tenant $($azure1.TenantId.Substring(0,8))..." -ForegroundColor Yellow
Write-Host "    Tokens GitHub/Slack: $($tok1.Substring(0,15))..." -ForegroundColor Yellow
Write-Host "    Mots de passe (5+) : Format Corp${year}X! (fictifs)" -ForegroundColor White
Write-Host "    Cle SSH RSA        : Incluse dans SSH_KEYS_SERVEURS.txt" -ForegroundColor White
Write-Host "    IBAN               : $iban1" -ForegroundColor White
Write-Host ""
Write-Host "  Fichiers crees : $($allFiles.Count)" -ForegroundColor White
Write-Host "  Taille totale  : $([math]::Round($totalSize/1KB,1)) KB" -ForegroundColor White
Write-Host ""
Write-Host "  Fichiers cibles pour la demo ransomware:" -ForegroundColor Red
Write-Host "  $docDir\Confidentiel\" -ForegroundColor Red
Write-Host "  $base\Documents\Credentials_Backup\" -ForegroundColor Red
Write-Host ""
Write-Host "  PROCHAINE ETAPE:" -ForegroundColor DarkYellow
Write-Host "  1. Ouvrir Explorateur Windows -> montrer les fichiers a l'audience" -ForegroundColor Gray
Write-Host "  2. Ouvrir CREDENTIALS_ACCES_SYSTEMES.txt pour l'effet WOW" -ForegroundColor Gray
Write-Host "  3. Lancer edr_master_suite.ps1 -> les modules vont trouver ces fichiers" -ForegroundColor Gray
Write-Host ""
Write-Host "  NETTOYAGE APRES DEMO:" -ForegroundColor DarkYellow
Write-Host "  Remove-Item '$base\Documents\$($P.Folder)' -Recurse -Force" -ForegroundColor Cyan
Write-Host "  Remove-Item '$base\Documents\Credentials_Backup' -Recurse -Force" -ForegroundColor Cyan
Write-Host "  +================================================+" -ForegroundColor Green
