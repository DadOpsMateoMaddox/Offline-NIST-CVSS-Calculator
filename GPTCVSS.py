import openai
import tkinter as tk
from tkinter import ttk

# OpenAI API Key
openai.api_key = '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'

# Function to interact with ChatGPT API using the new ChatCompletion method
def interact_with_chatgpt(prompt):
    try:
        # Use the new Chat API for GPT-based models
        response = openai.ChatCompletion.create(
            model="gpt-4",  # You can also use gpt-3.5-turbo
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"Error: {e}"

# Function to generate prompt with CVSS variables based on the mode selected
def generate_prompt_with_cvss_variables(cvss_score, av, ac, au, c, i, a, mode):
    if mode == 'Explanation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "Can you provide an explanation based on this information?")
    elif mode == 'Recommendation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "What are some recommended actions for remediation?")
    elif mode == 'Attack Simulation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "Simulate a potential attack scenario based on this information.")
    else:
        prompt = "Invalid mode selected."
    
    return prompt

# Function to calculate CVSS score and automatically pass variables to ChatGPT
def calculate_cvss(event=None):
    # Weights for each metric
    av_weights = {"Network (N)": 1.0, "Adjacent Network (A)": 0.646, "Local (L)": 0.395, "Physical (P)": 0.2}
    ac_weights = {"Low (L)": 0.71, "High (H)": 0.35}
    au_weights = {"None (N)": 0.704, "Single (S)": 0.56, "Multiple (M)": 0.45}
    ci_weights = {"None (N)": 0.0, "Partial (P)": 0.275, "Complete (C)": 0.66}

    # Get the values from the combo boxes
    av = av_combo.get()
    ac = ac_combo.get()
    au = au_combo.get()
    c = c_combo.get()
    i = i_combo.get()
    a = a_combo.get()

    # Calculate Impact
    impact = 10.41 * (1 - (1 - ci_weights.get(c, 0)) * (1 - ci_weights.get(i, 0)) * (1 - ci_weights.get(a, 0)))

    # Calculate Exploitability
    exploitability = 20 * av_weights.get(av, 0) * ac_weights.get(ac, 0) * au_weights.get(au, 0)

    # Calculate Base Score
    if impact > 0:
        f_impact = 1.176
    else:
        f_impact = 0
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact

    # Cap the base score to a maximum of 10.0
    base_score = min(base_score, 10.0)

    # Show the CVSS Score in the result label
    result_label.config(text=f"CVSS Score: {base_score:.1f}")

    # Get the selected mode from the combo box
    mode = mode_combo.get()

    # Generate a prompt with CVSS variables and send it to ChatGPT
    prompt = generate_prompt_with_cvss_variables(base_score, av, ac, au, c, i, a, mode)
    response = interact_with_chatgpt(prompt)

    # Display the ChatGPT response
    response_textbox.config(state=tk.NORMAL)  # Enable textbox
    response_textbox.delete(1.0, tk.END)
    response_textbox.insert(tk.END, f"ChatGPT {mode}: {response}")
    response_textbox.config(state=tk.DISABLED)  # Disable textbox for editing

# Initialize the main window
root = tk.Tk()
root.title("Offline CVSS Calculator with ChatGPT Integration")

# Main frame to hold all widgets
main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Vulnerability Name Entry
vulnerability_name_label = ttk.Label(main_frame, text="Vulnerability Name:")
vulnerability_name_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
vulnerability_name_entry = ttk.Entry(main_frame)
vulnerability_name_entry.grid(row=0, column=1, padx=10, pady=10)

# Section 1: Access Vector (AV)
av_label = ttk.Label(main_frame, text="Access Vector (AV):")
av_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
av_combo = ttk.Combobox(main_frame, values=["Network (N)", "Adjacent Network (A)", "Local (L)", "Physical (P)"])
av_combo.grid(row=1, column=1, padx=10, pady=10)

# Section 2: Access Complexity (AC)
ac_label = ttk.Label(main_frame, text="Access Complexity (AC):")
ac_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
ac_combo = ttk.Combobox(main_frame, values=["Low (L)", "High (H)"])
ac_combo.grid(row=2, column=1, padx=10, pady=10)

# Section 3: Authentication (Au)
au_label = ttk.Label(main_frame, text="Authentication (Au):")
au_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
au_combo = ttk.Combobox(main_frame, values=["Multiple (M)", "Single (S)", "None (N)"])
au_combo.grid(row=3, column=1, padx=10, pady=10)

# Section 4: Confidentiality Impact (C)
c_label = ttk.Label(main_frame, text="Confidentiality Impact (C):")
c_label.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
c_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
c_combo.grid(row=4, column=1, padx=10, pady=10)

# Section 5: Integrity Impact (I)
i_label = ttk.Label(main_frame, text="Integrity Impact (I):")
i_label.grid(row=5, column=0, padx=10, pady=10, sticky=tk.W)
i_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
i_combo.grid(row=5, column=1, padx=10, pady=10)

# Section 6: AvailabilityIt looks like we were in the middle of adding a **mode selection dropdown** for ChatGPT options (such as "Explanation", "Recommendation", or "Attack Simulation"). This would allow users to choose the type of analysis they want from ChatGPT when interacting with the CVSS calculator.

### Continuing the Update:

# for adding **ChatGPT Mode Selection** and updating the interface:


# Section 6: Availability Impact (A)
a_label = ttk.Label(main_frame, text="Availability Impact (A):")
a_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)
a_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
a_combo.grid(row=6, column=1, padx=10, pady=10)

# Mode Selection for ChatGPT Interaction
mode_label = ttk.Label(main_frame, text="ChatGPT Mode:")
mode_label.grid(row=7, column=0, padx=10, pady=10, sticky=tk.W)
mode_combo = ttk.Combobox(main_frame, values=["Explanation", "Recommendation", "Attack Simulation"])
mode_combo.grid(row=7, column=1, padx=10, pady=10)

# Label to display the CVSS Score
result_label = ttk.Label(main_frame, text="CVSS Score: -", font=("Arial", 12, "bold"))
result_label.grid(row=8, column=0, columnspan=2, pady=10)

# Textbox to display ChatGPT response
response_textbox = tk.Text(main_frame, wrap="word", width=60, height=10)
response_textbox.grid(row=9, column=0, columnspan=2, padx=10, pady=10)
response_textbox.config(state=tk.DISABLED)  # Initially disable editing

# Button to calculate the CVSS score and generate ChatGPT response
calculate_button = ttk.Button(main_frame, text="Calculate CVSS", command=calculate_cvss)
calculate_button.grid(row=10, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI loop
root.mainloop()