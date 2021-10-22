# Response Team
#### _Forensic Windows_

### Étape n°1
**Énoncé** : _Our Security team identified a strange behaviour with a computer. They have sent you the proxy logs and have asked you to review it to identify if there is a malicious activity or not._

On nous donne un fichier .7z dans lequel on trouve un fichier Readme.txt et un fichier access.log.

**Readme.txt** :
> Step1:
Is there any suspicious activity ?
Rules:
To unlock the step2, find the malicious url
The format to use is the following:
sha256(XXX://domain:port/page1)
The sha256 hash must be in lowercase.

Le fichier .log contient des milliers de logs de requêtes HTTP. Impossible donc de chercher dans le fichier à la main. 
En regardant de plus près le format du flag demandé, on se rend compte qu'on attend de nous de trouver une URL au format XXX::domain:port/page1, ce qui élimine énormément de logs du fichier.

On construit alors une expression régulière, en admettant que le XXX correspond à http car c'est une URL malicieuse : 
```http://.*:[0-9]*/```. 
On utilise la commande grep et nous tombons sur des logs contenant la requête HTTP suivante:
```TCP_MISS/200 813 GET http://frplab.com:37566/sdhjkzui1782109zkjeznds```

Cette URL étant effectivement louche, on calcule le sha256 et l'étape n°1 est finie.

**FLAG** : 0cb9c24ae4d9d05096a9a837dcd0169e792369dcf48f7da456fda96638f47d18

### Étape n°2

Après avoir extrait les fichiers du nouveau .7z grâce au flag de l'étape précédente, on tombe sur le Readme suivant :
>Step2:
Can we find more information on the download ?
Rules:
To unlock the step3, you have to identify the name of the job.
Just use that name (casesensitive) to unlock the step3

Avec ça, nous avons un dossier rempli de fichiers .evtx, qui correspondent à des fichiers d'évènements Windows lisibles uniquement par le gestionnaire d'évènements. On trouve l'outil [EVTXtract](https://github.com/williballenthin/EVTXtract) qui permet de décoder ces fichiers et on écrit un petit script permettant de tous les décoder et de rediriger le résultat dans un fichier.

En cherchant le nom de domaine malicieux, à savoir frplab.com, dans le fichier, on tombe sur l'évènement suivant : [event.txt](event.txt).
On peut voir le nom du job demandé pour valider l'épreuve.

**FLAG** : qsljdsyy19872IFDND172537438eueir

### Étape n°3
>Step3:
What happen on the computer ? Is there any trace left ?
Rules:
To unlock the step4, you have to find a password.
Use it in (casesensitive) to unlock the step4

Pour cette étape, beaucoup de fichiers nous sont fournis : 
- Deux fichiers $MFT et $J
- Un dossier Downloader contenant tout un tas de fichiers système
- Un dossier Prefetch contenant des dizaines de fichiers .pf
- Un dossier Task, vide

On élimine le dossier Task et on s'intéresse au dossier Downloader, car ce challenge est en rapport avec un téléchargement malicieux. Après le traditionnel ```strings | grep``` sur la plupart des fichiers, on ne trouve rien d'intéressant car ces derniers ne contiennent que très peu de données.

Après quelques recherches, on élimine les fichiers .pf. Ce sont des prefetch files, donnant des informations sur les exécutables lancés sur la machine, telles que l'heure, le nombre d'exécution, le path, etc... Ce qui ne nous intéresse pas particulièrement.

Le fichier $MFT correspont à la Master File Table, présente dans le système de fichiers NTFS. On peut obtenir un aperçu de l'arborescence de fichiers grâce à [INXParse](https://github.com/williballenthin/INDXParse). Après de longs moments à fouiller dans la MFT, et n'obtenant rien de concret, on passe alors au dernier fichier : $J.

Ce fichier correspond aux logs des opérations faites sur des fichiers système de Windows. On trouve un outil appelé [USN-Journal-Parser](https://github.com/PoorBillionaire/USN-Journal-Parser) qui permet de lire ce fichier. On commence à chercher à partir de l'heure de la création du job dont parlait l'étape n°2, c'est-à-dire ```2021-08-18 09:38:34.875330```. On parcourt le fichier quelques temps puis on trouver un log décrivant un fichier au nom étrange : ```payload-aXRpc2Fsd2F5c3RoZXNhbWUK.001```. On remarque tout de suite le texte encodé en base64 que l'on s'empresse de décoder : ```itisalwaysthesame```. Ça ressemble fortement au début d'un flag. On trouve ensuite quatre autres fichiers de ce style, une fois décodés, nous obtenons la phrase suivante : ```itisalwaysthesame auserclickedonawrongfile wherecoulditbe thepa119737w@rdforthelaststepis alqjioue679AIEUSJ98```.

**FLAG** : alqjioue679AIEUSJ98


### Étape n°4
>Step4:
Find the file responsible of all of this
Rules:
The flag to submit must be in the following form:
SHA256(Datetime_in_local_timezone:full path of the file)
Ex: SHA256(2024-01-01T01:20:C:\eee\abc&#46;xxx)
The sha256 hash must be in lowercase

Pour cette dernière étape, on nous donne deux fichiers : NTUSER.dat et UsrClass.dat.
NTUSER.dat est un fichier propre à chaque utilisateur et contient la configuration du profil de l'utilisateur. UsrClass.dat contient des informations sur des dossiers ou des fichiers consultés par l'utilisateur. Ces deux fichiers stockent des informations venant de registres Windows. Naturellement, Usrclass.dat nous intéresse tout particulièrement. Après le traditionnel ```strings | grep``` qui ne donne rien d'intéressant, on utilise l'outil [RegRipper](https://github.com/keydet89/RegRipper3.0). Malgré l'utilisation de plugins très intéressants comme recentapps ou recentdocs, on ne trouve rien d'intéressant dans ce fichier.

On se tourne alors vers NTUSER.dat, on trouve grâce à ```strings``` la mention d'un fichier nommé mon_compte_formation.lnk. Ce fichier ne vient évidemment pas de Windows donc il nous intéresse. 
On utilise l'outil [Registry Explorer](https://ericzimmerman.github.io/#!index.md) qui nous permet d'avoir une arborescence des registres stockés dans NTUSER.dat. On recherche le nom ```mon_compte_formation```. On tombe sur six mentions de ce fichier et une de ces mentions contient une date au même format que celui demandé. On calcule le sha256 et on valide la quatrième épreuve.

**FLAG** : 02e7e0ee22695ab7f9299a1eef8a0227555004a70cafc87374612f82c42915e4

