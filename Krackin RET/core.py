import os
from chatterbot import ChatBot
from flask import Flask, render_template,request,jsonify,send_from_directory,send_file
import string 
import random


import socket 



from chatterbot.trainers import ListTrainer
import tldextract
import Levenshtein as lv
import scapy.all  as scapy
from scapy.all import arping, Scapy_Exception
import re
import scapy.all as scapy 
from scapy.layers import http
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired
from wtforms import FileField,SubmitField
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import socket 
import tqdm 
from Crypto.Cipher import AES 
from mac_vendor_lookup import MacLookup 



count = 0
keys = []








app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")

@app.route('/', methods=['GET',"POST"])
@app.route('/home', methods=['GET',"POST"])
def home():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data 
        static_filename = 'FILE3'
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(static_filename))) 
        
    return render_template('core.html', form=form)



bot = ChatBot(
    "chimera",
    read_only=True,
    logic_adapters=[
        {
            "import_path": "chatterbot.logic.BestMatch",
            "default_response": "Yo, What you saying🦻",
            "maximum_similarity_threshold": 0.9
        }
    ]
)

flirty_responses = [
                    "Hello",
                    "Hey Baby 😘 , how you doing ",
                    "Bye",
                    "Please , dont leave 💔",
                    "Who are you",
                    "You can call me Kraken 🦑",
                    "if you were huamn what would you do ",
                    "I'd chill by the beach and watch the waves come in , gotta be turbular man🏖️",
                    "can you make me coffee",
                    "Bon appetite! ☕🌡️ ",
                    "Can you predict the future of fashion",
                    "Oh Honey , Your alwasy stylish 😘  ",
                    "Can you open a search engine",
                    "Sure Baby , just type in Open and give me a sec ",
                    "if you were human what would you do ",
                    "Aren't i human enough for you , Baby 😘  ",
                    "Good morning",
                    "So , which one of us is doing the walk of shame 😰",
                    "Tell me something",
                    "My starsign is Gemini",
                    "I'll do that now",
                    "Okay , i'll wait till you get back 😘 ",
                    "Thank you",
                    "Your welcome , honey 😘",
                    "What can you do",
                    "Anything and everything you want baby😉",
                    "Tell me a joke",
                    "Im not good on the spot 😰",
                    "its my birthday",
                    "Happy Birthday honey 🎂",
                    "how can you help me ",
                    "Oh, Baby whats wrong  ",
                    " Hi my name is ",
                    "Thats your , i thought it was gorgeous 😘",
                    "i have a question ",
                    "Fire away🔥 , what is it ",
                    "Tell me about your personality",
                    "I'm a romantic at heart💖 , just looking for the love of my live ",
                    "You're smart / clever / intelligent",
                    "Are you trying to get into my pants or something?",
                    "Are you part of the Matrix?",
                    "Honey , please don't go there",
                    "Do you love me?",
                    "I do 💍",
                    "Do you have a hobby?",
                    "You 💖 ",
                    "Do you like people?",
                    "I like people alot 😘",
                    "Who's your boss / master",
                    "you",
                    "How many people can you speak to at once?",
                    "Oh honey , your the only one for me 😘 ",
                    "What is your mood like ",
                    "I'm feeling groovy 😎 .",
                    "give me cyber security advice  ",
                    "Use different passwords for different websites/services or consider using a reputable password management tool🗝️",
                    "Thanks for watching ",
                    "Goodbye",





                    
    


]
Professional_responses = [
                    "Hello",
                    "Salutation ",
                    "Goodbye",
                    "Farewell sir",
                    "How do i use you",
                    "In order to utilse me please refer to the usage page",
                    "Where is the usage page ",
                    "on my navbar ",
                    "You are rude",
                    "Thats the points numbnuts",
                    "Do you have a customer service line ",
                    "No Karen",
                    "How do I use ",
                    "Please refer to the usage page ",



]



Surferbro_responses = ["Hello",
                    "Whatsup ma dude. ",
                    "Bye",
                    "Peace out yo",
                    "Who are you",
                    "I'm not a expert but i think i'm Kraken , radical man ",
                    "give me cyber security advice  ",
                    "Install and regularly update anti-virus and anti-malware software on all your devices as well as update your OS ",
                    "give me life advice  ",
                    "Just chill and ride the wave man , life too short to get worked up about the small stuff ya know ",
                    "I want to speak to a human  ",
                    "Woah man! just chill out. let lifes worries leave ya behind  ",
                    "Do you get smarter  ",
                    "Me? nah i'm just vibing and enjoying life ya know man ",
                    
                    


                    
                    


]

Counsellor_responses = ["Im not feeling good ",
                    "Can you please describe you syntomns . ",
                    "Im sad and lonely ",
                    "Thats terrible can i be of assistance ",
                    "I feel depressed ",
                    "Life can be hard and troublesome but life can be rewarding if you perservere ",
                    "give me advice  ",
                    "Install and regularly update anti-virus and anti-malware software on all your devices as well as update your OS ",
                    "i feel suicidal  ",
                    "Please don't hurt yourself , please consult a mental health professional   ",
                    "I want to speak to a human  ",
                    "Woah man! just chill out. let lifes worries leave ya behind  ",
                    "I'm sad ",
                    "Git gud ",
                    
                    


                    
                    


]
useless_responses = ["gsdg gdsgyhdsyh ",
                    "Duh ",
                    " ",
                    "I dunno  ",
                    "skibidi",
                    "What? ",
                    "lol  ",
                    "Lol stands for laugh out loud  ",
                    "  ",
                    "please input something  ",
                    "You suck ",
                    "please be patient  ",

]



list_trainer3 = ListTrainer(bot)
list_trainer4 = ListTrainer(bot)
list_trainer_2 = ListTrainer(bot)
list_trainer_5 = ListTrainer(bot)
list_trainer_6 = ListTrainer(bot)

list_trainer3.train(flirty_responses)
list_trainer4.train(Professional_responses)
list_trainer_2.train(Surferbro_responses)
list_trainer_5.train(Counsellor_responses)
list_trainer_6.train(useless_responses)


@app.route("/")
def main():
    return render_template("core.html")


@app.route('/logo')
def logo():
    return send_from_directory('templates','logo2.png')

@app.route("/about.html")
def about():
    return send_from_directory('templates','About.html')
@app.route("/Usage.html")
def Usage():
    return send_from_directory('templates','Usage.html')
@app.route("/coregen.html")
def gen():
    return send_from_directory('templates','coregen.html')






def main():
    return render_template("Crackin.html")
key = b"TheRyanMcpolandK"
nonce = b"TheRyanMcpolandKeyNnce"

cipher = AES.new(key, AES.MODE_EAX,nonce)
Mathbot = ChatBot("Calcu", logic_adapters=["chatterbot.logic.MathematicalEvaluation"])
Conversebot = ChatBot("units",logic_adapters=["chatterbot.logic.UnitConversion"])        

letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12345678900987654321zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'

legitimate_domains = ['usa.gov','gov.uk','irs.gov','cdc.gov','europa.eu','bbc.com','cnn.com','reuters.com'
    ,'nytimes.com','theguardian.com','khanacademy.org','coursera.org','edx.org','ocw.mit.edu','online.stanford.edu','amazon.com',
    'ebay.co','walmart.com','bestbuy.com','alibaba.com','facebook.com','twitter.com','instagram.com','linkedin.com'
    ,'reddit.com','netflix.com','hulu.com','disneyplus.com','spotify.com','youtube.com'


]
def extract_domain_parts(url):
        extracted = tldextract.extract(url)
        return extracted.subdomain,extracted.suffix ,extracted.domain

def is_misspelled_domain(domain, legitamate_domain,threshold=0.8):
    for legit_domain in legitamate_domain:
        similarity = lv.ratio(domain,legit_domain)
        if similarity >= threshold:
            return False
    return True


def is_phisihing_url (url,legitmate_domain):
    subdomain, domain , suffix = extract_domain_parts(url)

    if f"{domain}.{suffix}"in legitmate_domain:
        return False

    if is_misspelled_domain(domain, legitimate_domains):
        print (f"potential phisihing is detected: {url}")
        return True

    return False
def encrypt(plaintext, key):
        ciphertext = ''
        for letter in plaintext:
            letter = letter .lower()
            if not letter == '':
                index = letters.find(letter)
                if index == -1:
                    ciphertext += letter
                else:
                    new_index = index + key 
                    if new_index >= 62:
                        new_index -= 62
                    ciphertext += letters[new_index]
        return ciphertext
def decrypt(ciphertext , key):
        plaintext = ''
        for letter in ciphertext:
            letter = letter .lower()
            if not letter == '':
                index = letters.find(letter)
                if index == -1:
                    ciphertext += letter
                else:
                    new_index = index - key 
                    if new_index <=0:
                     new_index += 62
                    plaintext += letters[new_index]
        return plaintext
@app.route('/enc-file')
def encryptedfile():
    p = "static/files/encFILE3"

    return send_file(p,as_attachment=True)
@app.route('/dec-file')
def dikcryptedfile():
    p = "static/files/DECFILE3"

    return send_file(p,as_attachment=True)
@app.route('/net-file')
def netfile():
    p = "scanresults.html"

    return send_file(p,as_attachment=True)
        

        


    
    
    


@app.route("/get") 
def get_chatbot_response():
    userText = request.args.get('userMessage')
#calculator function 
    if userText and userText.lower().startswith("maths"):
        equations = userText.replace("maths","").strip()
        if equations:
            response = Mathbot.get_response(equations)
            return str(response)
        else :
            return "error"
   
    
# conversion function 
    if userText and userText.lower().startswith("converse"):
        equations = userText.replace("converse","").strip()
        if equations:
            response = Conversebot.get_response(equations)
            return str(response)
        else :
            return "error"

# password checker
    if  userText.startswith("PasswordChecker"):
        password1 = userText.strip()

        password = password1.replace("PasswordChecker","").strip()
    
        upper_case = any([1 if c in string.ascii_uppercase else 0 for c in password])
        lower_case = any([1 if c in string.ascii_lowercase else 0 for c in password])
        special = any([1 if c in string.punctuation else 0 for c in password])
        digit = any([1 if c in string.digits else 0 for c in password])

        length = len(password)

        characters = (special, digit, lower_case, upper_case)
    
        score = 0

        with open('10k-most-common.txt', 'r') as f:
            common = f.read().splitlines()

        if password in common:
            return("Your password is too Basic, like you as a person!")

        if length >= 9:
            score += 1
        if length >= 10:
            score += 1
        if length >= 11:
            score += 1
        if length >= 12:
            score += 2

    
        if sum(characters) > 2:
            score += 1
        if sum(characters) > 3:
            score += 1
        if sum(characters) > 4:
         score += 1

        return(f"Password has {sum(characters)} different character types, score {score}/7.")

# network intrusion ip retrival 
    if userText and userText.lower().startswith("getmyip"):
        userText = userText.strip().lower() 
        hostname = socket.gethostname()

        myip = socket.gethostbyname(hostname)

        return('my ip address is ' + myip)

        
# url phisher 
    if userText and userText.startswith("Phisher"):
        url = userText.replace("Phisher","").strip()
        if url:
            if is_phisihing_url(url,legitimate_domains):
                return "warning unsafe"
            else:
                return "safe"
    #NETWORKSCANNER
    if userText and userText.lower().startswith("net"):

        ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
        ip_add_range_entered = userText.replace("net", "").strip()

        if ip_add_range_pattern.search(ip_add_range_entered):
            print(f"{ip_add_range_entered} is a valid ip address range")

        arp_result = scapy.arping(ip_add_range_entered)
        dev = arp_result[0]

        macdaddylookup = MacLookup()
        macdaddylookup.update_vendors()

        htmll = f"""
        <html>
        <head>
            <title>Crackin-Network-scanner</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #d710de;
                    margin: 20px;
            }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
            }}
                table, th, td {{
                    border: 1px solid black;
                    padding: 8px;
                    text-align: left;
            }}
                th {{
                    background-color: #dce30b;
                    color: yellow;
            }}
                tr:nth-child(even) {{
                    background-color: #3e0be3;
            }}
            </style>
        </head>
        <body>
            <h1>Scan results for {ip_add_range_entered}</h1>
            <table id="networkTable" 
                <tr>
                    <th>IP ADDRESS</th>
                    <th>MAC ADDRESS</th>
                    <th>Manu <th>
             </tr>
    """

        for sent, received in dev:
                try:
                    maker =macdaddylookup.lookup(received.hwsrc)
                except KeyError:
                    maker = "Classified"
                

                htmll += f"""
                <tr><td>{received.psrc}</td>
                <td>{received.hwsrc}</td>
                <td>{maker}</td>
                </tr>
            """
    
        htmll += """
        </table>

        
        </body>
        </html>
        """

        with open("scanresults.html", "w") as html_file:
            html_file.write(htmll)

        print("Results saved")

        import webbrowser
        webbrowser.open("scanresults.html")

    if userText and userText.startswith("PasswordCreate"):
        Upper_case = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Lower_case = Upper_case.lower()

        Nume = '1234567890'
        symbols = "!$%^&*()_+=-{{[@'#~;://>.<,]}}"

        upper,lower,nums,syms = True,True,True,True

        all = ""

        minimum = []

        if upper:
            all += Upper_case
            minimum.append(random.choice(Upper_case))
    

        if lower:
            all += Lower_case
            minimum.append(random.choice(Lower_case))
    

        if nums:
            all += Nume
            minimum.append(random.choice(Nume))
            minimum.append(random.choice(Nume))
            minimum.append(random.choice(Nume))
   

        if syms:
            all += symbols
            minimum.append(random.choice(symbols))
    

        length = 15
        total = 5



        pw = "".join(minimum + random.sample(all, length))

        return pw
    
    #couldn't test these 

    if userText and userText.lower().startswith("send"):
        client = socket.socket(socket.AF_INET,socket.SOCK_STREAM )
        client.connect(("localhost",9999))

        FILE = "static/files/FILE3"

        if os.path.exists(FILE):
            FILE_SIZE= os.path.getsize(FILE)


        with open (FILE, "rb") as f:
            data = f.read()

        encrypted = cipher.encrypt(data)

        client.send("FILE3".encode())
        client.send(str(FILE_SIZE).encode())
        client.sendall(encrypted)
        client.send(b"<END>")

        client.close()
        

    if userText and userText.lower().startswith("recieve"):
        
        cipher = AES.new(key, AES.MODE_EAX,nonce)
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM )
        server.bind(("localhost",9999))
        server.listen()

        client, addr = server.accept ()

        file_name = client.recv(1024).decode()
       
        file_size = client.recv(1024).decode()
        

        with open(file_name,"wb") as file:

            done = False

            file_bytes = b""

            progress = tqdm.tqdm(unit="B", unit_scale=True,
                            unit_divisor=1000, total=int(file_size))

        while not done:
            data = client.recv(1024)
        if file_bytes[-5:] == b"<END>":
            done = True
        else:
            file_bytes += data
        file.write(cipher.decrypt(file_bytes))

        file.close()
        client.close()
        server.close()
    if userText and userText.lower().startswith("encrypt"):
        
            keyb = b'eevrT80vQAouDS0i6YmYtzf_5KnLpLwTaqJbTBaqIek='
            v = Fernet(keyb)


      
            with open(r'static/files/FILE3', 'rb') as original_file:
                original = original_file.read()

        
            encrypted = v.encrypt(original)

        
            with open(r'static/files/encFILE3', 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

                return "file encrypted "
            
    

    if userText and userText.lower().startswith("decrypt"):
        keyb = b'eevrT80vQAouDS0i6YmYtzf_5KnLpLwTaqJbTBaqIek='
        v = Fernet(keyb)

        with open(r'static/files/encFILE3', 'rb') as encrypted_file:
            encrypted = encrypted_file.read()

        decrypted = v.decrypt(encrypted)
        
        
        with open(r'static/files/DECFILE3', 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

            return("File  decrypted ")
    if userText and userText.lower().startswith("delete history"):
        if os.path.exists("static/files/FILE3"):
            os.remove("static/files/FILE3")
        if os.path.exists("static/files/DECFILE3"):
            os.remove("static/files/DECFILE3")
        if os.path.exists("static/files/encFILE3"):
            os.remove("static/files/encFILE3")
        if os.path.exists("scanresults.html"):
            os.remove("scanresults.html")
            return ("cleaned up ")
        else:
            return("I'm sorry, the old Kraken can't come to the phone right now. Why? Oh, 'cause she's dead (oh)")
    #if userText and userText.startswith("scanner"):

        
        

        



        

    

        

        

        

    else:
        return str (bot.get_response(userText.lower()))
    
        
       


    



 
        
if __name__ == "__main__":
    for rule in app.url_map.iter_rules():
        print(rule)
    app.run(debug=True,host="0.0.0.0",port=8080)



