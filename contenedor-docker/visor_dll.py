import pefile
import tkinter as tk
from tkinter import filedialog
from configparser import ConfigParser

def get_exported_functions(dll_path):
    try:
        pe = pefile.PE(dll_path)

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            functions = []
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                functions.append(entry.name.decode('utf-8'))

            return functions

    except Exception as e:
        return []

    return []

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
    if file_path:
        selected_file_entry.delete(0, tk.END)
        selected_file_entry.insert(0, file_path)

def search_functions():
    dll_path = selected_file_entry.get()
    if dll_path:
        exported_functions = get_exported_functions(dll_path)
        functions_text.config(state="normal")
        functions_text.delete("1.0", "end")
        if exported_functions:
            for func_name in exported_functions:
                functions_text.insert("end", func_name + "()\n")
                
        else:
            functions_text.insert("end", "No se encontraron funciones exportadas")
        functions_text.config(state="disabled")

# Crear la ventana principal de Tkinter
root = tk.Tk()
root.title("DLL Function Viewer")
root.geometry("400x300")

# Cuadro de selección de archivo
file_frame = tk.Frame(root)
file_frame.pack(pady=10)

selected_file_label = tk.Label(file_frame, text="Archivo DLL:")
selected_file_label.pack(side="left")

selected_file_entry = tk.Entry(file_frame, width=30)
selected_file_entry.pack(side="left")

browse_button = tk.Button(file_frame, text="Explorar", command=browse_file)
browse_button.pack(side="left")

# Encabezado y área de texto para mostrar funciones
functions_frame = tk.Frame(root)
functions_frame.pack()

header_label = tk.Label(functions_frame, text="Funciones:")
header_label.pack()

functions_text = tk.Text(functions_frame, wrap="none", state="disabled")
functions_text.pack(fill="both", expand=True)

# Botón para buscar funciones
search_button = tk.Button(root, text="Buscar funciones", command=search_functions)
search_button.pack()

# Configuración a partir de un archivo INI
config = ConfigParser()
config.read('config.ini')  # Ajusta el nombre de tu archivo INI

# Configuración de la ventana principal
root.title(config.get('MainWindow', 'title'))
root.geometry(config.get('MainWindow', 'geometry'))

# Configuración del cuadro de selección de archivo
selected_file_label.config(text=config.get('FileSelection', 'label_text'))
browse_button.config(text=config.get('FileSelection', 'button_text'))

root.mainloop()
