## TP Sécurité Offensive Camouflage-de-m4lware

Ce projet académique démontre les techniques de création et d'obfuscation de payloads malveillants dans un environnement de laboratoire contrôlé. L'objectif est de comprendre les mécanismes d'attaque par reverse shell et les méthodes de dissimulation de code malveillant pour sensibiliser aux enjeux de cybersécurité.

 Objectifs Pédagogiques

Comprendre le fonctionnement du framework Metasploit et de Meterpreter
Maîtriser les techniques d'obfuscation de code et d'encodage XOR
Analyser les méthodes de camouflage de malware par fusion avec des applications légitimes
Étudier les techniques d'évasion (anti-sandbox, anti-debug)
Évaluer la détection par les antivirus via VirusTotal: https://www.virustotal.com/gui/home/upload

 Architecture du Laboratoire
Environnement de Test

Machine attaquante #1 : Kali Linux (192.168.56.109)

Génération du payload avec Metasploit
Hébergement du serveur HTTP
Écoute des connexions reverse shell


Machine attaquante #2 : Windows (192.168.56.108)

Fusion du payload avec l'application légitime
Création de l'installateur via IExpress


Machine cible : Windows XP (192.168.56.103)

Système vulnérable pour les tests
Exécution du malware camouflé



 Compétences Techniques Développées
1. Exploitation avec Metasploit

Utilisation de msfvenom pour générer des payloads reverse TCP
Configuration et utilisation du module multi/handler
Gestion des sessions Meterpreter
Paramétrage LHOST/LPORT pour les connexions inversées

2. Programmation et Obfuscation

Développement Python : création d'un script d'obfuscation avancé
Encodage XOR avec génération de clés aléatoires
Programmation C : développement de loaders custom
Compilation croisée avec MinGW (i686-w64-mingw32-gcc)
Techniques d'optimisation de code (-O2, -s, -mwindows)

3. Techniques d'Évasion

Anti-sandbox : implémentation de délais aléatoires (Sleep)
Anti-debug : utilisation de IsDebuggerPresent()
Obfuscation :

Noms de variables aléatoires
Encodage des noms d'API Windows
Injection de code inutile (junk code)


Chargement dynamique : résolution d'API via GetProcAddress

4. Gestion Mémoire Windows

Allocation mémoire avec VirtualAlloc
Modification des permissions avec VirtualProtect
Exécution de shellcode en mémoire (in-memory execution)
Compréhension des flags de protection mémoire (PAGE_READWRITE, PAGE_EXECUTE_READ)

5. Ingénierie Sociale et Camouflage

Fusion d'applications : combinaison malware + logiciel légitime (PuTTY)
Utilisation d'IExpress pour créer des installateurs autonomes
Scripting Batch : automatisation du déploiement
Techniques de distribution via serveur HTTP

6. Analyse de Sécurité

Évaluation de la détection antivirus (VirusTotal : 23/71 détections)
Analyse comportementale du malware
