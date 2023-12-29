import os

from jinja2 import Template

template = ''
with open("templates/template.html", "r") as Tem:
    template = Template(Tem.read())


def render_page(root: str, port: int, usrname: str, base64str: str):
    cur_dir = '/'.join(root.split('/')[2:])
    parent = '/'.join(cur_dir.split('/')[:-1])
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
                'ref':'"' + ref + '"',
                'href': href,
                'type': 'Folder' if os.path.isdir(os.path.join(root, f)) else 'File',
                'delete': 'delete'
            })
    
    return template.render(
        usrname=usrname,
        base64str=base64str,
        root=root,
        files=files,
        parentUrl=f'"http://localhost:{port}/{parent}?SUSTech-HTTP=0"'
    )

