- All Annexes previously outlined covered on a 24/7 basis
- Audits would be quick and complete
- Automated complete inventory
  * MAC Address/Name
  * Accounts
  * Software installed
  * Processes running
- Policy Enforcement
  * Locked screen
    - `gsettings get org.gnome.desktop.screensaver lock-enabled`
    - `gsettings get org.gnome.desktop.screensaver lock-delay`
    - `kreadconfig5 --file kscreenlockerrc --group Daemon --key Autolock`
    - 'kreadconfig5 --file kscreenlockerrc --group Daemon --key Timeout`
  * Whitelist/Blacklist software
    - Check dpkg/rpm/pacman
    - Check Flatpak via libloading, libflatpak.so, and `flatpak_installation_list_installed_refs`
    - Check homedir for executable binaries?
  * Disk encryption
    - Check for LUKS usage on disks homedirs are on
    - Check for eCryptfs usage in homedirs if LUKS is not in use
- Self-Service and Support
  * Configure software installs and allow user installation
    - Support dpkg/rpm/pacman
    - Support Flatpak via libflatpak.so
  * Remote desktop for assistance
    - Rig up something with VNC, stunnel, and TURN?
  * Password resets - lock out assist
    - Pretty easy; hash password and set via chpasswd command
- Package generator that specifies e.g. flatpak dependencies or not based on admin preferences?
