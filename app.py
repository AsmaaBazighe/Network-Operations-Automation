from flask import Flask, render_template, request
import pandas as pd
import nmap
from getpass import getpass
from netmiko import ConnectHandler

app = Flask(__name__)

app.static_folder = 'templates/static'

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/configure", methods=["POST"])
def configure():
    user = request.form.get("username")
    psw = request.form.get("password")
    cisco=pd.read_excel("C://Users//PC//Desktop//BAZIGHE Asmaa//code//ocp.xlsx")
    n=len(cisco)
    cisco["username"]= [user]*n
    cisco["password"]=[psw]*n
    results = []
    for _,device in cisco.iterrows():
        connection = ConnectHandler(**device)
        for ligne in open("C://Users//PC//Desktop//BAZIGHE Asmaa//code//ocp.txt","r"):
            results.append(connection.send_command(ligne))
        connection.disconnect()
    return render_template('index.html', result="\n".join(results))

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == 'POST':
        ip=request.form.get("adress")
        masque=request.form.get("masque")
        plage=ip+masque
        scanner=nmap.PortScanner()
        scanner.scan(plage)
        df=pd.DataFrame(scanner.all_hosts(),columns=['Adresse IP'])
        df['state']=(scanner[ip].state())
        df.to_excel("scan.xlsx")
        print("fin de scan")
        result = df.to_html(classes='table table-striped', index=False)
        return render_template('scan.html', result=result)
    else:
        return render_template('scan.html')

@app.route("/backupssh", methods=["GET", "POST"])
def backupssh():
    if request.method == 'POST':
        user = request.form.get("username")
        psw = request.form.get("password")
        cisco=pd.read_excel("C://Users//PC//Desktop//BAZIGHE Asmaa//code//ocp.xlsx")
        n=len(cisco)
        cisco["username"]= [user]*n
        cisco["password"]=[psw]*n
        L=[]
        for ligne in open("C://Users//PC//Desktop//BAZIGHE Asmaa//code//config.txt","r"):
            L.append(ligne)
        results = []
        for _,device in cisco.iterrows():
            connection = ConnectHandler(**device)
            x="Connection à: "+device['host']
            results.append(x)
            results.append(connection.send_config_set(L))
            with open(f" {device['host']}.txt", 'w') as file:
                file.write(connection.send_config_set(L))
            connection.save_config()
            connection.disconnect()
            x="Fin de connection à: "+device['host']
            results.append(x)
        return render_template('backupssh.html', result="\n".join(results))
    else:
        return render_template('backupssh.html')

if __name__ == '__main__':
    app.run(debug=True)
