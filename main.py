import tkinter as tk
from tkinter import messagebox

import ecb
import cbc

current_mode = None #Either CBC or EBC


def show_input_page(mode):
    global current_mode
    current_mode = mode
    
    mode_label.config(text=f"Mode: {current_mode}")
    
    selection_frame.pack_forget()
    input_frame.pack(expand=True, fill="both")

def show_selection_page():
    entry_box.delete(0, tk.END)
    
    input_frame.pack_forget()
    selection_frame.pack(expand=True, fill="both")

def on_submit():
    user_input = entry_box.get()

    if not user_input:
        messagebox.showwarning("Warning", "The input cannot be empty")
        return

    try:
        msg = ""
        if current_mode == "ECB":
            msg = ecb.encryptMessage(user_input)
            print(f"Encrypted with ECB: {msg}")
            
        elif current_mode == "CBC":
            msg = cbc.encryptMessage(user_input) 
            print(f"Encrypted with CBC: {msg}")

        messagebox.showinfo("Success", f"Encrypted Message ({current_mode}):\n{msg}")
        entry_box.delete(0, tk.END)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption:\n{e}")




#-------------------------------------------------------------------------------------#



#GUI Setup
root = tk.Tk()
root.title("RSA-Cypher App")
root.geometry("1300x850")
root.configure(background='#629FAD')

btn_font = ("Arial", 12, "bold")


# FRAME 1: Selection Page
selection_frame = tk.Frame(root, bg='#629FAD')

intro_label = tk.Label(
    selection_frame, 
    text="Welcome to RSA Cipher App\nPlease choose your encryption mode:", 
    bg='#629FAD', 
    font=("Arial", 16, "bold"),
    fg="#EDEDCE"
)

intro_label.pack(pady=40)


btn_ecb = tk.Button(
    selection_frame, 
    text="RSA - ECB Mode", 
    width=20, 
    height=2, 
    font=btn_font,
    command=lambda: show_input_page("ECB")
)
btn_ecb.pack(pady=10)


btn_cbc = tk.Button(
    selection_frame, 
    text="RSA - CBC Mode", 
    width=20, 
    height=2, 
    font=btn_font,
    command=lambda: show_input_page("CBC") 
)
btn_cbc.pack(pady=10)



# FRAME 2: Input Page
input_frame = tk.Frame(root, bg='#629FAD')

mode_label = tk.Label(
    input_frame, 
    text="Mode: Unknown", 
    bg='#629FAD', 
    font=("Arial", 20, "bold"),
    fg="#EDEDCE"
)
mode_label.pack(pady=30)

instruction_label = tk.Label(
    input_frame, 
    text="Enter the message you want to encrypt:", 
    bg='#629FAD',
    font=("Arial", 12)
)

instruction_label.pack(pady=10)

entry_box = tk.Entry(input_frame, width=40, font=("Arial", 12))
entry_box.pack(pady=10)

submit_button = tk.Button(
    input_frame, 
    text="Encrypt Message", 
    font=btn_font, 
    bg="white",
    command=on_submit
)
submit_button.pack(pady=20)

back_button = tk.Button(
    input_frame, 
    text="Back to Menu", 
    command=show_selection_page
)
back_button.pack(pady=10)


selection_frame.pack(expand=True, fill="both")

root.mainloop()