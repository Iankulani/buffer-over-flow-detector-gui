# -*- coding: utf-8 -*-
"""
Created on Tue Feb 14 05:49:25 2025

@author: IAN CARTER KULANI

"""

import tkinter as tk
from tkinter import messagebox
import re

class BufferOverflowDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Buffer Overflow Detection Tool")
        self.root.geometry("500x400")
        
        # Instruction Label
        self.label = tk.Label(root, text="Enter your C/C++ code to check for buffer overflows:")
        self.label.pack(pady=10)
        
        # Text box for code input
        self.code_input = tk.Text(root, width=60, height=10)
        self.code_input.pack(pady=10)
        
        # Button to check for vulnerabilities
        self.check_button = tk.Button(root, text="Check for Buffer Overflow", command=self.check_buffer_overflow)
        self.check_button.pack(pady=10)
        
        # Result label
        self.result_label = tk.Label(root, text="", fg="red")
        self.result_label.pack(pady=20)

    def check_buffer_overflow(self):
        # Get the C/C++ code from the text box
        code = self.code_input.get("1.0", tk.END)

        if not code.strip():
            messagebox.showerror("Input Error", "Please enter some C/C++ code.")
            return

        # Analyze the code for common buffer overflow patterns
        vulnerabilities = self.analyze_code(code)

        # Display result
        if vulnerabilities:
            self.result_label.config(text=f"Potential Vulnerabilities Found:\n{vulnerabilities}")
        else:
            self.result_label.config(text="No buffer overflow vulnerabilities detected.")

    def analyze_code(self, code):
        vulnerabilities = []

        # Common buffer overflow patterns based on unsafe functions
        unsafe_functions = ["gets", "scanf", "strcpy", "strcat", "sprintf", "vsprintf"]

        for func in unsafe_functions:
            if re.search(r"\b" + func + r"\b", code):
                vulnerabilities.append(f"Use of unsafe function: {func}()")

        # Checking for lack of boundary checks (simplified)
        if re.search(r"\b(strcpy|sprintf|scanf|gets)\s*\((?!.*\[\d+])", code):
            vulnerabilities.append("Possible unsafe use of function without boundary check.")

        # You can add more rules here for different patterns known to lead to buffer overflow

        return "\n".join(vulnerabilities) if vulnerabilities else None


# Main function to set up the GUI
def main():
    root = tk.Tk()
    app = BufferOverflowDetector(root)
    root.mainloop()

if __name__ == "__main__":
    main()
