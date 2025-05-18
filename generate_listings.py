import os

def generate_listings(directory):
    paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.h')):  # Only include C source/header files
                rel_path = os.path.join(root, file).replace('_','\_')
                paths.append(f"\\lstinputlisting[language=C,caption={{{rel_path}}}]{{{rel_path}}}")
    paths.sort()
    for x in paths:
        print(x)

if __name__ == "__main__":
    src_dir = "chqc-512/src"
    generate_listings(src_dir)
