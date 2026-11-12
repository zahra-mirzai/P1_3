from microbit import *
import radio                                              #le squelette du code pour le micro:bit baby fourni par le staff ucl
import random
import music

#Can be used to filter the communication, only the ones with the same parameters will receive messages
#radio.config(group=23, channel=2, address=0x11111111)
#default : channel=7 (0-83), address = 0x75626974, group = 0 (0-255)

nonce_counter = 0      #pour que les nonces soient uniques pour chaque msg


#----------------------Entre ces pointillés c'est du code qu'on peut ajouter/ ne fait pas partie du squelette fourni par le staff UCL-------------------------------

_____________________________________Code1__________________________________________________________________________________________________
# Ce morceau de code là, peut être encore amélioré et y a un problème de son avec l'émission de la music, ça beugue au début, à corriger
# Sert à détecter les sons pour afficher un msg qu'on peut éventuellement remplacer par un logo
# Le seuil de chaque volume détecté, je l'ai choisi sur base de rien du tout donc à voir si ça correspond à la réalité
# Le thème des musiques est à changer car c'est des sons de jeux qui ne correspond pas à la situation au moment t

dernier_etat = 0

while True:
    niveau = microphone.sound_level()

    if niveau > 120:
        etat = 3
    elif niveau > 100:
        etat = 2
    elif niveau > 80:
        etat = 1
    else:
        etat = 0

    if etat != dernier_etat:
        if etat == 3:
            display.scroll("Tres agite", delay=100, wait=False)
            music.play(music.POWER_UP, wait=False)
        elif etat == 2:
            display.scroll("Agite", delay=100, wait=False)
            music.play(music.JUMP_UP, wait=False)
        elif etat == 1:
            display.scroll("Reveille", delay=100, wait=False)
            music.play(music.BA_DING, wait=False)
        dernier_etat = etat

    sleep(100)


    if pin_logo.is_touched():
        display.show(Image.HEART)
    else:
        display.clear()

    message = radio.receive()
    if message:
        display.scroll(message)
    if button_a.is_pressed():
         radio.send("0x01|5|Salut")
         display.clear()
    
    sleep(100)
________________________________________________Fin du code 1__________________________________________________________________________________________________
#---------------------------------------------------------------------------------------------------------------------------------------------------------------

def hashing(string):
	"""
	Hachage d'une chaîne de caractères fournie en paramètre.
	Le résultat est une chaîne de caractères.
	Attention : cette technique de hachage n'est pas suffisante (hachage dit cryptographique) pour une utilisation en dehors du cours.

	:param (str) string: la chaîne de caractères à hacher
	:return (str): le résultat du hachage
	"""
	def to_32(value):
		"""
		Fonction interne utilisée par hashing.
		Convertit une valeur en un entier signé de 32 bits.
		Si 'value' est un entier plus grand que 2 ** 31, il sera tronqué.

		:param (int) value: valeur du caractère transformé par la valeur de hachage de cette itération
		:return (int): entier signé de 32 bits représentant 'value'
		"""
		value = value % (2 ** 32)
		if value >= 2**31:
			value = value - 2 ** 32
		value = int(value)
		return value

	if string:
		x = ord(string[0]) << 7
		m = 1000003
		for c in string:
			x = to_32((x*m) ^ ord(c))
		x ^= len(string)
		if x == -1:
			x = -2
		return str(x)
	return ""
    
def vigenere(message, key, decryption=False):
    text = ""
    key_length = len(key)
    key_as_int = [ord(k) for k in key]

    for i, char in enumerate(str(message)):
        key_index = i % key_length
        #Letters encryption/decryption
        if char.isalpha():
            if decryption:
                modified_char = chr((ord(char.upper()) - key_as_int[key_index] + 26) % 26 + ord('A'))
            else : 
                modified_char = chr((ord(char.upper()) + key_as_int[key_index] - 26) % 26 + ord('A'))
            #Put back in lower case if it was
            if char.islower():
                modified_char = modified_char.lower()
            text += modified_char
        #Digits encryption/decryption
        elif char.isdigit():
            if decryption:
                modified_char = str((int(char) - key_as_int[key_index]) % 10)
            else:  
                modified_char = str((int(char) + key_as_int[key_index]) % 10)
            text += modified_char
        else:
            text += char
    return text
    
def send_packet(key, type, content):
    """
    Envoie de données fournie en paramètres
    Cette fonction permet de construire, de chiffrer puis d'envoyer un paquet via l'interface radio du micro:bit

    :param (str) key:       Clé de chiffrement
           (str) type:      Type du paquet à envoyer
           (str) content:   Données à envoyer
	:return none
    """
	global nonce_counter
	nonce_counter += 1    #donc direct le premier msg a un nonce de 1
	nonce = str(nonce_counter)   
	contenu = nonce + ":" + content
	packet = type + "|" + str(len(contenu)) + "|" + contenu      # version clair de packet
	if key:                                                     # si il y a une clé alors on chiffre sinon on envoie tel quel et du côté parent on le reçoit tel quel
		packet = vigenere(packet, key)                           # version brouillée de packet
	radio.send(packet)

#Decrypt and unpack the packet received and return the fields value
def unpack_data(encrypted_packet, key):
    """
    Déballe et déchiffre les paquets reçus via l'interface radio du micro:bit
    Cette fonction renvoit les différents champs du message passé en paramètre

    :param (str) encrypted_packet: Paquet reçu
           (str) key:              Clé de chiffrement
	:return (srt)type:             Type de paquet
            (int)lenght:           Longueur de la donnée en caractères
            (str) message:         Données reçues
    """


#Unpack the packet, check the validity and return the type, length and content
def receive_packet(packet_received, key):
    """
    Traite les paquets reçue via l'interface radio du micro:bit
    Cette fonction permet de construire, de chiffrer puis d'envoyer un paquet via l'interface radio du micro:bit
    Si une erreur survient, les 3 champs sont retournés vides

    :param (str) packet_received: Paquet reçue
           (str) key:              Clé de chiffrement
	:return (srt)type:             Type de paquet
            (int)lenght:           Longueur de la donnée en caractère
            (str) message:         Données reçue
    """
    
#Calculate the challenge response
def calculate_challenge_response(challenge):
    """
    Calcule la réponse au challenge initial de connection avec l'autre micro:bit

    :param (str) challenge:            Challenge reçu
	:return (srt)challenge_response:   Réponse au challenge
    """
    
#Ask for a new connection with a micro:bit of the same group
def establish_connexion(key):
    """
    Etablissement de la connexion avec l'autre micro:bit
    Si il y a une erreur, la valeur de retour est vide

    :param (str) key:                  Clé de chiffrement
	:return (srt)challenge_response:   Réponse au challenge
    """

def main():
    return True