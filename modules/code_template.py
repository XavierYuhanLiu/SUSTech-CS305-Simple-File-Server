import os

from jinja2 import Template

template = ''
with open("templates/template.html", "r") as Tem:
    template = Template(Tem.read())


def render_page(root: str, port: int, usrname: str, base64str: str):
    cur_dir = '/'.join(root.split('/')[2:])
    parent = '/'.join(cur_dir.split('/')[:-1])
    files = getFileList(root, port, cur_dir)
    enable = chechPrivilege(usrname, cur_dir)
    
    return template.render(
        usrname=usrname,
        base64str='"base ' + base64str + '"',
        root=root,
        cur_dir='"' + cur_dir + '"',
        files=files,
        parentUrl=f'"http://localhost:{port}/{parent}?SUSTech-HTTP=0"',
        enable=enable
    )

def getFileList(root, port, cur_dir):
    files = []

    if os.path.exists(root):
        for f in os.listdir(root):
            if f == '.DS_Store':
                continue
            ref = cur_dir + f'/{f}'
            href = f'"http://localhost:{port}/{ref.strip("/")}?SUSTech-HTTP=0"'
            files.append({
                'name': f,
                'name_with_quote': '"' + f + '"',
                'name_with_quote_fragment': '"' + f + '#fragment"',
                'ref':'"' + ref + '"',
                'size': '"' + str(os.path.getsize(os.path.join(root, f))) + '"',
                'href': href,
                'href_chunked': href + "?chunked=1",
                'type': 'Folder' if os.path.isdir(os.path.join(root, f)) else 'File',
                'delete': 'delete'
            })
            
    return files

def chechPrivilege(usrname, cur_dir):
    username_in_url = cur_dir.split('/')[0]
    
    enable = username_in_url == usrname
    return enable

