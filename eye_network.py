#!/usr/bin/python3
import time,sys

try:
    from tqdm import tqdm
except ImportError:
    print("[ - ] The module `tqdm` is Not Find\n[ - ] Please Install `tqdm` Library")
    exit()

try:
    import click
except ImportError:
    print("[ - ] The module `click` is Not Find\n[ - ] Please Install `click` Library")
    exit()
    
try:
    import interruptingcow
except ImportError:
    print("[ - ] The module `interruptingcow` is Not Find\n[ - ] Please Install `scapy` Library")
    exit()
    
try:

    from scapy.layers.inet  import * # IP, TCP , ICMP , etc.. 
    from scapy.sendrecv     import * # send, sniff, AsyncSniffer, sr1
    from scapy.utils        import * # hexdump
    from scapy.config       import * # conf
    import scapy.modules.nmap   as a # nmap_fp
    
except ImportError:
    print("[ - ] The module `scapy` is Not Find\n[ - ] Please Install `scapy` Library")
    exit()


# Color
R = '\033[1;31m'
T = '\033[1;33m'
B = '\033[1;34m'
G = '\033[1;32m'
W = '\033[1;37m'
N = '\033[0m'


class WIR:
    def __init__(self, model, timeout, HEXDUMP, filter):
        self.type    = model
        self.timeout = timeout
        self.SUM     = int()
        self.GET     = None
        self.hexdump = HEXDUMP
        self.filter  = filter
        self.DO      = None
    
    def get_hex_ips(self):

        self.GET = AsyncSniffer(iface=self.type)
        
        try:
       
            with tqdm(interruptingcow.timeout(self.timeout*60),bar_format=f"Model: [ {G}{self.type if self.type != None else 'Any'}{N} ] Type: [ {G}{self.filter if self.filter != 'any' else 'Any'}{N} ] TimeOut: [ {G}{self.timeout}m{N} ]\n"):
                
                while True:
                    
                    self.GET.start()
                    time.sleep(0.10)
                    self.GET.stop()
                    
                    try:                 
                        if self.hexdump == False:
                            
                            if 'T' == self.filter[0].upper():
                                self.DO = self.GET.results[TCP].res
                            
                            elif 'U' == self.filter[0].upper():
                                self.DO = self.GET.results[UDP].res

                            else:
                                self.DO = self.GET.results.res


                            for vlu in self.DO:
                            
                                print('%s[ %s ]%s %s' % 
                                    (B,conf.color_theme.id(self.SUM, fmt="%04i")
                                    ,N,
                                    self.style(vlu.summary())))
                            
                                if 'Payload' in self.style(vlu.summary()):
    
                                    
                                    print(hexdump(vlu, dump=True).replace('.', f'{R}.{N}'))
                        
                                self.SUM+=1
                        
                        else:
                            self.GET.results.hexraw()

                    except Exception as e:
                        print(f'[ - ] Error for {e}')
                        continue
        
        except OSError:
            print(f'{R}Sorry this is Big {self.SUM*60} Noses {N}')
            exit() 
        
                    
        except RuntimeError:
            exit()

        
    def style(self, text):
        if 'TCP'   in text.split(): text = text.replace('TCP', f'{T}TCP{N}')
        if 'UDP'   in text.split(): text = text.replace('UDP', f'{G}UDP{N}')
        if 'ARP'   in text.split(): text = text.replace('ARP', f'{W}ARP{N}')
        if 'Ether' in text.split(): text = ''.join(text.split('Ether /'))
        if 'Raw'   in text.split(): text = text.replace('Raw', f'{T}Payload{N}')
        if 'IP'    in text.split(): text = ''.join(text.split('IP /'))
        if '/'     in text.split(): text = text.replace('/', f'{B}AND{N}')
        if '>'     in text.split(): text = text.replace('>', f'{B}TO{N}')
        return text
        

@click.command()
@click.option('-m','--model',type=click.STRING,help='Model listen like wlan0 , eth0 , etc...')
@click.option('-t','--timeout', default=5,type=click.INT, help='Number timeout for exit for the script')
@click.option('-H','--hexdump', is_flag=True,help='Acts in the form of hexdump')
@click.option('-f','--filter', default='any',type=click.STRING, help='Filter types TCP or UDP')
@click.version_option(help='v0.1')
@click.help_option(help='For the assistant')

def main(model, timeout, hexdump, filter):
    """This program will listen to all the connections in your device like wlan0 or eth0, etc ..."""
    try:
        get_wifi = WIR(model, timeout, hexdump, filter).get_hex_ips()
    except scapy.error.Scapy_Exception:
        print(f"{R}Not Find this {model} model in Your Network{N}")
         
if __name__ == "__main__":
    main()
