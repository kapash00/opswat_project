import json
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PythonApplication1 import readfile, virustotalhash

# משתנים לשמירת נתיבי הקבצים כדי שנוכל לגשת אליהם אחר כך
report_path = ""
whitelist_path = ""

def select_report():
    global report_path
    filepath = filedialog.askopenfilename(
        title="Choose the Opswat report",
        filetypes=[("Text Files", "*.txt"), ("JSON Files", "*.json"), ("All Files", "*.*")]
    )
    if filepath:
        report_path = filepath
        lbl_report_path.config(text=filepath)

def select_whitelist():
    global whitelist_path
    filepath = filedialog.askopenfilename(
        title="Choose the Whitelist",
        filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    if filepath:
        whitelist_path = filepath
        lbl_whitelist_path.config(text=filepath)

def run_analysis():
    # נוודא שהמשתמש באמת בחר קובץ לפני שמריצים
    if report_path:
        print(f"File== {report_path}")
        # הפעלת הפונקציות מתוך הקובץ המקושר
        allhash = readfile(report_path)
        virustotalhash(whitelist_path,allhash)
        messagebox.showinfo("File path =",f"")
    else:
        print("Error-- choose a file!")

# --- בניית החלון הראשי ---
root = tk.Tk(screenName="Opswat report scanner", baseName="Opswat report scanner")
root.title("Opswat report scanner")
root.geometry("450x300")

# כפתור ותווית לדוח
btn_report = tk.Button(root, text=" Opswat report ", command=select_report, width=20)
btn_report.pack(pady=(20, 5))
lbl_report_path = tk.Label(root, text="No file selected", fg="gray")
lbl_report_path.pack()

# כפתור ותווית ל-Whitelist
btn_whitelist = tk.Button(root, text=" Whitelist", command=select_whitelist, width=20)
btn_whitelist.pack(pady=(20, 5))
lbl_whitelist_path = tk.Label(root, text="No file selected", fg="gray")
lbl_whitelist_path.pack()

# כפתור הרצה
btn_run = tk.Button(root, text="Start script!", command=run_analysis, bg="lightblue", font=("Arial", 12, "bold"))
btn_run.pack(pady=30)

#כפתור סגירה
#button = tk.Button(root, text="Exit", command=root.destroy)
#button.pack()

root.mainloop()