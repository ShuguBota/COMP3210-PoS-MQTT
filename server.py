#!/usr/bin/env python3
# Run this on Win10/Linux/Mac to listen for messages from the MQTT broker
# change the subscribe line to listen for your own messages
import paho.mqtt.client as mqtt
import time
import json
import rsa

print('Server started...')
print('Beginning initialization...')
print('Generating RSA keys')
(publicKey, privateKey) = rsa.newkeys(1024)
publicKey_Client = None

file_name = 'data.json'

print('Reading the database')
with open(file_name, 'r') as file:
    data = json.load(file)

def on_message(client, userdata, message):
    print("Received message: " , str(message.payload.decode('utf-8')))
    try:
        json_message = json.loads(message.payload.decode('utf-8'))
    except json.JSONDecodeError:
        try:
            decrypted_message = rsa.decrypt(bytes.fromhex(str(message.payload.decode('utf-8'))),privateKey)
            json_message = json.loads(decrypted_message.decode('utf-8'))
            print('<+> Decrypted message: ', json_message)
        except rsa.DecryptionError:
            print('Message could not be drcrypted by the private key of the server')
            return

    if 'type' in json_message:
        if(json_message['type'] == 'connection'):
            global publicKey_Client 
            publicKey_Client = rsa.PublicKey(json_message['publicKey']['n'], json_message['publicKey']['e'])
            message = json.dumps({'type': 'connection_confirmation', 'publicKey' : {"n": publicKey.n, "e": publicKey.e}})
            #print(message)
            client.publish('csc1u20/client', message)
    if 'id' in json_message:
        message = {'result': False}
        global data
        for item in data:
            if(item['uid'] == json_message['id']):
                if(item['a'] - json_message['a'] >= 0):
                    message = {'result': True}
                    item['a'] -= json_message['a']
                    with open(file_name, 'w') as file:
                        json.dump(data, file)
                    break
                else:
                    break
        
        encrypted_bytes = rsa.encrypt(json.dumps(message).encode('utf-8'), publicKey_Client)
        encrypted_hex = ''.join('{:02x}'.format(byte) for byte in encrypted_bytes).upper()
        client.publish('csc1u20/client', encrypted_hex)


mqttBroker = "srv03183.soton.ac.uk"

print('Connecting to the broker: ' + mqttBroker)
client = mqtt.Client("SimpleListen")
client.connect(mqttBroker)

print('Subscribing to the topic: csc1u20/server')
print('Beginning loop...')
client.loop_start()

client.subscribe("csc1u20/server")
client.on_message = on_message

time.sleep(1000)

client.loop_stop()
