from microbit import *
import radio                                              #le squelette du code pour le micro:bit baby fourni par le staff ucl
import random
import music

#Can be used to filter the communication, only the ones with the same parameters will receive messages
radio.config(group=23, channel=2, address=0x11111111)
#default : channel=7 (0-83), address = 0x75626974, group = 0 (0-255)

key = "KEYWORD"            
connexion_key = None       
nonce_list = set()         
dernier_recu = 0           
nonce_counter = 0          
milk_count = 0             
# Types : 1 connexion, 2 confirmation, 3 état d'éveil, 4 lait, 5 pleurs
list_type = ["1", "2", "3", "4", "5"]

# Seuils de détection : À CALIBRER si nécessaire
SEUIL_MOUVEMENT = 300      
NB_MESURES = 50            
SEUIL_BRUIT = 120          
NB_BRUIT_MIN = 20          # mesures bruyantes nécessaires pour parler de pleurs
IMAGES = {"0": Image.ASLEEP, "1": Image.CONFUSED, "2": Image.ANGRY}




#----------------------Entre ces pointillés c'est du code qu'on peut ajouter/ ne fait pas partie du squelette fourni par le staff UCL-------------------------------

#_____________________________________Code1__________________________________________________________________________________________________
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
#________________________________________________Fin du code 1__________________________________________________________________________________________________
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
	if key:
        paquet_clair = vigenere(encrypted_packet, key, decryption=True)
    else:
        paquet_clair = encrypted_packet
    morceaux = paquet_clair.split("|", 2)
    if len(morceaux) != 3 or not morceaux[1].isdigit() or int(morceaux[1]) != len(morceaux[2]):
        return "", "", ""
    return morceaux[0], int(morceaux[1]), morceaux[2]


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
	type, longueur, contenu = unpack_data(packet_received, key)
    if type == "" or type not in list_type:
        return "", "", ""
    if ":" not in contenu:
        return "", "", ""
    nonce, message = contenu.split(":", 1)
    if nonce in nonce_list:
        return "", "", ""
    nonce_list.add(nonce)     # mémorisé en dernier, une fois tout validé
    return type, len(message), message


    
#Calculate the challenge response
def calculate_challenge_response(challenge):
    """
    Calcule la réponse au challenge initial de connection avec l'autre micro:bit

    :param (str) challenge:            Challenge reçu
	:return (srt)challenge_response:   Réponse au challenge
    """
	random.seed(int(challenge))
    challenge_response = random.randint(0, 999999)   # mêmes bornes des deux côtés
    return str(challenge_response)
    
#Ask for a new connection with a micro:bit of the same group
def establish_connexion(key):
    """
    Etablissement de la connexion avec l'autre micro:bit
    Si il y a une erreur, la valeur de retour est vide

    :param (str) key:                  Clé de chiffrement
	:return (srt)challenge_response:   Réponse au challenge
    """
	challenge = str(random.randint(0, 999999))
    challenge_response = calculate_challenge_response(challenge)
    send_packet(key, "1", challenge)
    debut = running_time()
    while running_time() - debut < 3000:
        paquet = radio.receive()
        if paquet is not None:
            type, longueur, message = receive_packet(paquet, key)
            if type != "" and message == hashing(challenge_response):
                return challenge_response
    return ""

# --------------------------------- Fonctions ajoutées par notre groupe --------------------------------------
def handle_incoming():
    """Lit la radio et mémorise la quantité de lait envoyée par le parent."""
    global milk_count, dernier_recu
    paquet = radio.receive()
    if paquet is not None and connexion_key:
        type, longueur, message = receive_packet(paquet, connexion_key)
        if type != "":
            dernier_recu = running_time()
        if type == "4" and message.isdigit():
            milk_count = int(message)

def analyze():
    """
    Observe l'enfant pendant 5 secondes (mouvements + bruit).
    Retourne (état, pleurs) en texte : état "0" endormi, "1" agité, "2" très agité ;
    pleurs "0" ou "1". Une chute (freefall) donne tout de suite "2".
    """
    mouvements = 0
    bruit = 0
    x0, y0, z0 = accelerometer.get_values()
    for i in range(NB_MESURES):
        sleep(100)
        handle_incoming()
        if button_b.was_pressed():
            display.show(milk_count)
        if accelerometer.was_gesture("freefall"):
            return "2", "0"
        x, y, z = accelerometer.get_values()
        delta = abs(x - x0) + abs(y - y0) + abs(z - z0)
        if delta > SEUIL_MOUVEMENT:
            mouvements += 1
        x0, y0, z0 = x, y, z
        if microphone.sound_level() > SEUIL_BRUIT:
            bruit += 1
    pleurs = "0"
    if bruit >= NB_BRUIT_MIN:
        pleurs = "1"
    if mouvements > 25:
        return "2", pleurs
    if mouvements > 5:
        return "1", pleurs
    return "0", pleurs
#---------------------------------------------------------------------------------------------------------
def main():
	global connexion_key, dernier_recu
    radio.on()
    display.show(Image.HEART_SMALL)
    reponse = ""
    while reponse == "":
        nonce_list.clear()
        reponse = establish_connexion(key)
    connexion_key = key + reponse
    dernier_recu = running_time()

    etat_precedent = ""
    pleurs_precedent = ""
    while True:
        etat, pleurs = analyze()
        display.show(IMAGES[etat])      # À FAIRE : rassurer le bébé (son doux)
        if etat != etat_precedent:
            send_packet(connexion_key, "3", etat)
            etat_precedent = etat
        if pleurs != pleurs_precedent:
            send_packet(connexion_key, "5", pleurs)
            pleurs_precedent = pleurs
   
        if running_time() - dernier_recu > 30000:
            reponse = ""
            while reponse == "":
                nonce_list.clear()
                reponse = establish_connexion(key)
            connexion_key = key + reponse
            dernier_recu = running_time()
            etat_precedent = ""        # on renvoie l'état courant au parent
            pleurs_precedent = ""
    main()
