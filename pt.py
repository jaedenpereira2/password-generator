import random
import string
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, simpledialog
import datetime

# generate password
def generate_password():
    length = length_var.get()
    if length < 4:
        messagebox.showerror("Error", "Password length should be at least 4")
        return

    characters = ""
    if use_letters.get():
        characters += string.ascii_letters
    if use_numbers.get():
        characters += string.digits
    if use_symbols.get():
        characters += string.punctuation

    if not characters:
        messagebox.showerror("Error", "Select at least one character type")
        return

    password = ''.join(random.choice(characters) for _ in range(length))
    password_var.set(password)
    check_strength(password)

# check password strength
def check_strength(password):
    strength_label.config(fg="white")
    if len(password) < 6 or password.isnumeric() or password.isalpha():
        strength_var.set("Weak")
        strength_label.config(fg="red")
    elif len(password) >= 6 and any(char in string.punctuation for char in password):
        strength_var.set("Medium")
        strength_label.config(fg="orange")
    if len(password) >= 10 and any(char in string.punctuation for char in password) and any(char.isdigit() for char in password):
        strength_var.set("Strong")
        strength_label.config(fg="green")

# copy password
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_var.get())
    root.update()
    messagebox.showinfo("Success", "Password copied to clipboard!")

# save password to file
def save_password():
    password = password_var.get()
    category = category_var.get()

    if not password:
        messagebox.showerror("Error", "No password generated yet!")
        return

    if category == "Select Category":
        messagebox.showerror("Error", "Please select a category!")
        return

    with open("saved_passwords.txt", "a") as file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp} | {category} | {password}\n")

    messagebox.showinfo("Success", "Password saved successfully!")

# search passwords by category
def search_passwords():
    category = search_category_var.get()
    if category == "Select Category":
        messagebox.showerror("Error", "Please select a category to search!")
        return

    try:
        with open("saved_passwords.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords found!")
        return

    global filtered_lines
    filtered_lines = [line for line in lines if f"| {category} |" in line]

    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    if filtered_lines:
        for result in filtered_lines:
            result_text.insert(tk.END, result)
    else:
        result_text.insert(tk.END, "No passwords found for this category.")
    result_text.config(state="disabled")

# delete passwords by category
def delete_passwords():
    category = search_category_var.get()
    if category == "Select Category":
        messagebox.showerror("Error", "Please select a category to delete!")
        return

    try:
        with open("saved_passwords.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords found!")
        return

    new_lines = [line for line in lines if f"| {category} |" not in line]
    if len(new_lines) == len(lines):
        messagebox.showerror("Error", f"No passwords found for '{category}' to delete!")
        return

    with open("saved_passwords.txt", "w") as file:
        file.writelines(new_lines)

    messagebox.showinfo("Success", f"All '{category}' passwords deleted!")
    search_passwords()  # Refresh search results

# edit a password
def edit_password():
    selected_text = result_text.get(tk.SEL_FIRST, tk.SEL_LAST)
    if not selected_text:
        messagebox.showerror("Error", "Please select a password to edit!")
        return

    # Extract the timestamp, category, and old password
    parts = selected_text.strip().split(" | ")
    if len(parts) != 3:
        messagebox.showerror("Error", "Invalid selection!")
        return

    old_password = parts[2]
    new_password = tk.simpledialog.askstring("Edit Password", f"Enter new password for:\n{selected_text}")
    if not new_password:
        return

    try:
        with open("saved_passwords.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords found!")
        return

    with open("saved_passwords.txt", "w") as file:
        for line in lines:
            if old_password in line:
                file.write(line.replace(old_password, new_password))
            else:
                file.write(line)

    messagebox.showinfo("Success", "Password updated!")
    search_passwords()  # Refresh search results

# Creating main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("500x700")
root.configure(bg="#2c3e50")

# UI Elements
title_label = tk.Label(root, text="Random Password Generator", font=("Arial", 14, "bold"), bg="#2c3e50", fg="white")
title_label.pack(pady=10)

length_label = tk.Label(root, text="Enter Password Length:", font=("Arial", 12), bg="#2c3e50", fg="white")
length_label.pack()

length_var = tk.IntVar(value=8)
length_entry = tk.Entry(root, textvariable=length_var, font=("Arial", 12), width=5)
length_entry.pack(pady=5)

# Checkboxes for character type
use_letters = tk.BooleanVar(value=True)
use_numbers = tk.BooleanVar(value=True)
use_symbols = tk.BooleanVar(value=True)

letters_check = tk.Checkbutton(root, text="Include Letters", variable=use_letters, font=("Arial", 10), bg="#2c3e50", fg="white", selectcolor="#2c3e50")
letters_check.pack()

numbers_check = tk.Checkbutton(root, text="Include Numbers", variable=use_numbers, font=("Arial", 10), bg="#2c3e50", fg="white", selectcolor="#2c3e50")
numbers_check.pack()

symbols_check = tk.Checkbutton(root, text="Include Symbols", variable=use_symbols, font=("Arial", 10), bg="#2c3e50", fg="white", selectcolor="#2c3e50")
symbols_check.pack()

generate_button = tk.Button(root, text="Generate Password", font=("Arial", 12), command=generate_password, bg="#1abc9c", fg="white")
generate_button.pack(pady=10)

password_var = tk.StringVar()
password_entry = tk.Entry(root, textvariable=password_var, font=("Arial", 12), width=30, state="normal")
password_entry.pack(pady=5)

# Password strength indicator
strength_var = tk.StringVar(value="")
strength_frame = tk.Frame(root, bg="#2c3e50")
strength_frame.pack(pady=5)
strength_label_text = tk.Label(strength_frame, text="Password Strength: ", font=("Arial", 10), bg="#2c3e50", fg="white")
strength_label_text.pack(side=tk.LEFT)
strength_label = tk.Label(strength_frame, textvariable=strength_var, font=("Arial", 10, "bold"), bg="#2c3e50", fg="white")
strength_label.pack(side=tk.LEFT)

copy_button = tk.Button(root, text="Copy to Clipboard", font=("Arial", 12), command=copy_to_clipboard, bg="#e74c3c", fg="white")
copy_button.pack(pady=5)

# Save Password Feature
save_frame = tk.Frame(root, bg="#2c3e50")
save_frame.pack(pady=5)

save_label = tk.Label(save_frame, text="Save to Category:", font=("Arial", 12), bg="#2c3e50", fg="white")
save_label.pack(side=tk.LEFT, padx=5)

category_var = tk.StringVar(value="Select Category")
category_menu = ttk.Combobox(save_frame, textvariable=category_var, values=["Work", "Personal", "Social Media", "Custom"], font=("Arial", 12), state="readonly", width=15)
category_menu.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(root, text="Save Password", font=("Arial", 12), command=save_password, bg="#3498db", fg="white")
save_button.pack(pady=5)

# Search & Edit Feature
search_label = tk.Label(root, text="Search by Category:", font=("Arial", 12), bg="#2c3e50", fg="white")
search_label.pack(pady=5)

search_category_var = tk.StringVar(value="Select Category")
search_category_menu = ttk.Combobox(root, textvariable=search_category_var, values=["Work", "Personal", "Social Media", "Custom"], font=("Arial", 12), state="readonly")
search_category_menu.pack(pady=5)

search_button = tk.Button(root, text="Search Passwords", font=("Arial", 12), command=search_passwords, bg="#f1c40f", fg="black")
search_button.pack(pady=5)

delete_button = tk.Button(root, text="Delete Passwords", font=("Arial", 12), command=delete_passwords, bg="#e74c3c", fg="white")
delete_button.pack(pady=5)

# Results display
result_text = scrolledtext.ScrolledText(root, width=50, height=10, font=("Arial", 10), state="disabled")
result_text.pack(pady=10)

edit_button = tk.Button(root, text="Edit Selected Password", font=("Arial", 12), command=edit_password, bg="#8e44ad", fg="white")
edit_button.pack(pady=5)

# Run the GUI
root.mainloop()
