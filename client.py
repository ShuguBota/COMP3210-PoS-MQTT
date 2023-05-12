# send data MQTT to our VM
# Change the mqtt_topic to yourID/temperature
# SPDX-FileCopyrightText: 2021 ladyada for Adafruit Industries
# SPDX-License-Identifier: MIT
import ssl
import socketpool
import wifi
import adafruit_minimqtt.adafruit_minimqtt as mqtt
import board
import busio
from time import sleep
from adafruit_pn532.i2c import PN532_I2C
import adafruit_rsa
import digitalio
import adafruit_dotstar as dotstar
import json

def hex_to_bytes(hex_string):
    bytes_array = bytearray()
    for i in range(0, len(hex_string), 2):
        byte = int(hex_string[i:i+2], 16)
        bytes_array.append(byte)
    return bytes_array

class Main:
    ### Topic Setup ###
    mqtt_topic_server = "csc1u20/server"
    mqtt_topic_client = "csc1u20/client"
    mqttClient = None

    ### NFC ###
    pn532 = None

    ### Encryption Keys ###
    publicKey = None
    privateKey = None
    publicKey_Server = None

    ### Transfer Result ###
    msg_received = False

    ### Led ###
    boardLed = None

    ### MQTT Functions ###

    # Define callback methods which are called when events occur
    # pylint: disable=unused-argument, redefined-outer-name
    def connect(self, mqtt_client, userdata, flags, rc):
        # This will be called when the mqtt_client is connected successfully to the broker.
        print("Connected to MQTT Broker")
        print("Flags: {0}\n RC: {1}".format(flags, rc))

    def disconnect(self, mqtt_client, userdata, rc):
        # called when the mqtt_client disconnects
        print("Disconnected from MQTT Broker!")

    def publish(self, mqtt_client, userdata, topic, pid):
        # This method is called when the mqtt_client publishes data to a feed.
        print("Published to {0} with PID {1}".format(topic, pid))

    def on_message(self, mqtt_client, topic, message):
        print("Received message: " , message)
        try:
            json_message = json.loads(message)
        except Exception:
            try:
                m = hex_to_bytes(str(message))
                #print(m)
                decrypted_message = adafruit_rsa.decrypt(m, self.privateKey)
                json_message = json.loads(decrypted_message)
                print('<+> Decrypted message: ', json_message)
            except adafruit_rsa.DecryptionError:
                print('Message could not be drcrypted by the private key of the client')
                return

        if 'result' in json_message: 
            if(json_message['result'] == True):
                self.led[0] = (0, 255, 0)
                self.msg_received = True
            else:
                self.led[0] = (255, 0, 0)
                self.msg_received = True

        if 'type' in json_message:
            if(json_message['type'] == 'connection_confirmation'):
                self.publicKey_Server = adafruit_rsa.PublicKey(json_message['publicKey']['n'], json_message['publicKey']['e'])
                #print(self.publicKey_Server)
                self.msg_received = True

    def connectInternet(self):
        # pylint: disable=no-name-in-module,wrong-import-order
        try:
            from secrets import secrets
        except ImportError:
            print("WiFi secrets are kept in secrets.py, please add them there!")
            raise

        print("Connecting to %s" % secrets["ssid"])
        wifi.radio.connect(secrets["ssid"], secrets["password"])
        print("Connected to %s!" % secrets["ssid"])

    def setupNFC(self):
        print('Configuring the NFC')
        # Configure I2C bus
        i2c = busio.I2C(board.SCL, board.SDA)

        # Create PN532 object
        self.pn532 = PN532_I2C(i2c)

        # Configure PN532
        self.pn532.SAM_configuration()

    def setupMQTTClient(self):
        print('Configuring the MQTT protocol')
        # Create a socket pool
        pool = socketpool.SocketPool(wifi.radio)

        # Set up a MiniMQTT Client
        self.mqtt_client = mqtt.MQTT(
            broker="srv03183.soton.ac.uk",
            #broker="192.168.175.4",
            port=1883,
            username="none",
            password="non",
            socket_pool=pool,
            ssl_context=ssl.create_default_context(),
        )

        # Connect callback handlers to mqtt_client
        self.mqtt_client.on_connect = self.connect
        self.mqtt_client.on_disconnect = self.disconnect
        self.mqtt_client.on_publish = self.publish
        self.mqtt_client.on_message = self.on_message

    def setupLed(self):
        led = digitalio.DigitalInOut(board.LED)
        led.direction = digitalio.Direction.OUTPUT

    def keyExchange(self):
        message = {'type': 'connection', 'publicKey' : {'n' : self.publicKey.n, 'e' : self.publicKey.e}}
        self.mqtt_client.publish(self.mqtt_topic_server, json.dumps(message))

        self.awaitResponse()

    def generateKeys(self):
        print('Generating RSA keys')
        (self.publicKey, self.privateKey) = adafruit_rsa.newkeys(1024)

    def __init__(self):
        self.led = dotstar.DotStar(board.APA102_SCK, board.APA102_MOSI, 1)
        self.led[0] = (255, 255, 0) #Yellow color

        self.generateKeys()

        self.connectInternet()
        self.setupNFC()
        self.setupMQTTClient()

        print("Attempting to connect to %s" % self.mqtt_client.broker)
        self.mqtt_client.connect()

        #Subscribe to receive messages
        self.mqtt_client.subscribe(self.mqtt_topic_client)

        self.setupLed()

        ### Key exchange ###
        print('Beginning the exchange of keys process')
        self.keyExchange()


        print('Initialization finished...')
        self.led[0] = (0, 0, 0) #Turn off led after initialization

    def awaitResponse(self):
        while not self.msg_received:
            self.mqtt_client.loop()
        
        self.msg_received = False

    def readUUID(self):
        #Wait for a tag to be scanned
        print('Waiting for RFID/NFC card...')
        while True:
            #Check if a tag is present
            uid = self.pn532.read_passive_target(timeout=0.5)
            if uid is not None:
                uid_str = str([hex(i) for i in uid])

                message = {'id': uid_str, 'a': 5}
                
                encrypted_bytes = adafruit_rsa.encrypt(json.dumps(message).encode('utf-8'), self.publicKey_Server)
                encrypted_hex = ''.join('{:02x}'.format(byte) for byte in encrypted_bytes).upper()
                #print(encrypted_hex)
                print('Card read with id: ' + uid_str)
                self.mqtt_client.publish(self.mqtt_topic_server, encrypted_hex)
                self.led[0] = (0, 0, 255)
                break

        self.awaitResponse()

        sleep(5) #Sleep for 5 seconds so I can see the lights

        #print("Disconnecting from %s" % self.mqtt_client.broker)
        #self.mqtt_client.disconnect()

print('Card reader started...')
print('Beginning initialization...')
main = Main()

print('Beginning loop...')
while True:
    main.led[0] = (0, 0, 0)
    main.readUUID()