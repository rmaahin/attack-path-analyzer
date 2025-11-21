FROM soc-helper:latest

# 2. Set Environment Variables (Global Access)
ENV PATH="/opt/env/bin:$PATH"

# 3. Auto-activate for Interactive Shells
RUN echo "source /opt/env/activate" >> ~/.bashrc

# 4. Set the Working Directory
# This acts as the default "cd". When you log in, you will land here
# instead of the system root.
WORKDIR /mnt

# 6. Default Command
CMD ["bash"]
