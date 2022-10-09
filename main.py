from shodanApi import *


try:
    print('''##### Main Menu Shodan API #####
    
    [1] Banner Count
    [2] Scan Host (Recon)
    [3] Exit
    ''')

    opsi = int(input("Pilih Nomor Opsi : "))

    if opsi == 1:
        banner = input("Masukan Banner kemudian Enter : ")
        bannerCount(banner)
    elif opsi == 2:
        host = input("Masukan IP dari Host kemudian Enter : ")
        hostInfo(host)
    elif opsi == 3:
        print("\nBye.")
        exit()
    else:
        print(f"\ntidak ada opsi No {opsi}")
except ValueError:
    print("\nInputkan nomor dari opsi!")
except KeyboardInterrupt:
    print("\nBye.")
    exit()
except Exception as error:
    print(f"\n{error}")
