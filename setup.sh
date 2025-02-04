echo "Setting up Raspberry Pi"

echo "Updating and Upgrading"
sudo apt update && sudo apt upgrade -y

echo "Installing Docker"
sudo apt install docker-compose -y

# get username
username=$(whoami)
echo "Adding ${username} to docker group"
sudo usermod -aG docker $username

echo "Expanding Filesystem"
sudo raspi-config --expand-rootfs

echo "Configuration complete. Rebooting..."
sudo reboot
