# TP Sécurité Offensive : Camouflage de Malw4re

##  Description

Ce projet académique démontre les techniques de création et d'obfuscation de payloads malveillants dans un environnement de laboratoire contrôlé. L'objectif est de comprendre les mécanismes d'attaque par reverse shell et les méthodes de dissimulation de code malveillant pour sensibiliser aux enjeux de cybersécurité.

##  Objectifs Pédagogiques

- Comprendre le fonctionnement du framework Metasploit et de Meterpreter
- Maîtriser les techniques d'obfuscation de code et d'encodage XOR
- Analyser les méthodes de camouflage de malware par fusion avec des applications légitimes
- Étudier les techniques d'évasion (anti-sandbox, anti-debug)
- Évaluer la détection par les antivirus via [VirusTotal](https://www.virustotal.com/gui/home/upload)

##  Architecture du Laboratoire

### Environnement de Test

#### Machine Attaquante #1 : Kali Linux
- **Adresse IP** : `192.168.56.109`
- **Rôle** :
  - Génération du payload avec Metasploit
  - Hébergement du serveur HTTP
  - Écoute des connexions reverse shell

#### Machine Attaquante #2 : Windows
- **Adresse IP** : `192.168.56.108`
- **Rôle** :
  - Fusion du payload avec l'application légitime
  - Création de l'installateur via IExpress

#### Machine Cible : Windows XP
- **Adresse IP** : `192.168.56.103`
- **Rôle** :
  - Système vulnérable pour les tests
  - Exécution du malware camouflé

##  Compétences Techniques Développées

### 1. Exploitation avec Metasploit

- Utilisation de `msfvenom` pour générer des payloads reverse TCP
- Configuration et utilisation du module `multi/handler`
- Gestion des sessions Meterpreter
- Paramétrage LHOST/LPORT pour les connexions inversées

### 2. Programmation et Obfuscation

#### Python
- Création d'un script d'obfuscation avancé
- Encodage XOR avec génération de clés aléatoires

#### C
- Développement de loaders custom
- Compilation croisée avec MinGW (`i686-w64-mingw32-gcc`)
- Techniques d'optimisation de code (`-O2`, `-s`, `-mwindows`)

### 3. Techniques d'Évasion

#### Anti-Sandbox
- Implémentation de délais aléatoires (`Sleep`)

#### Anti-Debug
- Utilisation de `IsDebuggerPresent()`

#### Obfuscation
- Noms de variables aléatoires
- Encodage des noms d'API Windows
- Injection de code inutile (junk code)
- Chargement dynamique : résolution d'API via `GetProcAddress`

### 4. Gestion Mémoire Windows

- Allocation mémoire avec `VirtualAlloc`
- Modification des permissions avec `VirtualProtect`
- Exécution de shellcode en mémoire (in-memory execution)
- Compréhension des flags de protection mémoire (`PAGE_READWRITE`, `PAGE_EXECUTE_READ`)

### 5. Ingénierie Sociale et Camouflage

- Fusion d'applications : combinaison malware + logiciel légitime (PuTTY)
- Utilisation d'IExpress pour créer des installateurs autonomes
- Scripting Batch : automatisation du déploiement
- Techniques de distribution via serveur HTTP

### 6. Analyse de Sécurité

- Évaluation de la détection antivirus (VirusTotal : 23/71 détections)
- Analyse comportementale du malware

##  Technologies Utilisées

| Catégorie | Outils |
|-----------|--------|
| **OS** | Kali Linux, Windows XP, Windows (dev) |
| **Frameworks** | Metasploit Framework, Meterpreter |
| **Langages** | Python, C, Batch |
| **Compilateurs** | MinGW (i686-w64-mingw32-gcc) |
| **Outils Windows** | IExpress, VirtualAlloc API, VirtualProtect API |
| **Analyse** | VirusTotal |

##  Résultats

- **Taux de détection initial** : 23/71 moteurs antivirus (VirusTotal)
- **Techniques d'évasion** : Anti-sandbox et anti-debug implémentées avec succès
- **Camouflage** : Fusion réussie avec application légitime (PuTTY)

**Note** : La cybersécurité offensive doit toujours être pratiquée de manière éthique et responsable. Ce projet vise à former les futurs professionnels de la sécurité à comprendre les menaces pour mieux les prévenir.
