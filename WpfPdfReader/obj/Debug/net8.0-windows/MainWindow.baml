   M S B A M L   `   `   `  ����  WpfPdfReader    WpfPdfReader.MainWindow   5   	   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	     � Title$&   PDF Vulnerability Scanner Reader��5   	   $	��700��5   	   $
��1000��6   ���#2C2F33 � WindowStyle$
 None=�5   	    � 
ResizeMode$ CanResizeWithGrip=�5   	    � WindowStartupLocation$ CenterScreen=�5	   	    � 	Resources 5         ButtonStyle �� 
TargetType �� Property �� Value �� 
TargetType	 �� CornerRadius  CloseButtonStyle  ExpanderStyle  CustomScrollViewerStyle��%�  &	        &	 0    &	 `    &	 �    �� 5   
   " ��6$   .�5      ��  � �� �#7289DA6+   �� 5       � ��
 �����6+   �� 5       � ��$
 10,5q�6(   �� 5       � ��
 ���� 6,   �� 5       �@�Cursor$
 Hand��6'   �� 5       � ��$ 5q�6'   �� 5       � ��$ 16(�6)   �� 5       � ��$ 0q�60   �� 5       � �� 5      �� 5      " ��6&   .R�5      �� #��z��6!   $	 5��5   !   #��z��5   !   #��z��5   !   ._�5      �� $��Center=�6/   $��Center=�6L   5      5      5       5!      �� 5#   
   " ��6)   .�5$      ��  � �� �#FF00006+   �� 5%       � ��
 �����6+   �� 5&       � ��$
 10,5q�6(   �� 5'       � ��
 ���� 6,   �� 5(       �@�Cursor$
 Hand��6'   �� 5)       � ��$ 5q�6'   �� 5*       � ��$ 16(�6)   �� 5+       � ��$ 0q�60   �� 5,       � �� 5-      �� 5.      " ��6&   .R�5/      �� #��z��6!   $	 5��50   !   #��z��51   !   #��z��52   !   ._�53      �� $��Center=�6/   $��Center=�6L   54      55      57      58      �� 5:   
   " 9�6&   .�5;      ��  � �� �#2C2F336+   �� 5<       � ��
 �����6+   �� 5=       � ��$	 0,5q�6'   5>      �� 5@   
   " ��60   .�5A      ��  � �� �#23272A6+   �� 5B       � �� �#4F545C6,   �� 5C       � ��$ 1q�60   �� 5D       � ��$ 10q�6(   5E      5F      .��5H      �� ���#4F545C$��1q�6#   ._�5I   
   � 
 � RowDefinitions
 5J      �� 5K      $
��Auto �6    �� 5L      $��* �6    .+�5O      � ���#23272A � ColumnDefinitions 5P      �� 5Q      $��* �6'   �� 5R      $
��Auto �6'   .+�5U      �� $&�� PDF Vulnerability Scanner Reader��6   $��18(�6D   $
��Bold"�6R   ���#FFFFFF$��20,10q�6y   $��Center=�6�   �� 5V      -   5        $��1��5V      $��X��6)   #��[ 65   $
��10,5q�6_   6m   5W      � 5Y      $��1��6   $��20q�6    
 5Z      �� 5[      $
��Auto �6$   �� 5\      $��* �6$   .+�5_      �� -   5         ��Name$ ReadPdfButton��5_      $��Scan PDF��60   #��[  6_   $
��Left=�6�   $��0,0,0,20q�6�   �� 5`      -   5        $ SendInfoButton��5`      $��	Send Info��61   #��[  6b   $
��Left=�6�   $��	0,20,0,20q�6�   �� 5b      $��1��6   $
��Auto=�6,   $��Disabled=�6O   #��[ 6x   .��5c      �� -   5         ��Name$ FindingsItemsControl��5c   #   ��5d      �� 5e      .R�5f   "   9� #��[ 6+   ��6R   �� *Title+��5g   &   �� 5h   *   .R�5i   .   �� $
��Wrap=�6I   $
��Bold"�6]   ��68   �� 6]   5j   +   .��5l   &   �� $��20,10q�61   .+�5m   *   �� ��67   �� *	Details+��5n   .   �� 5o   2   .R�5p   6   �� $��0,0,0,15q�6A   .+�5q   :   �� $
��Bold"�6Y   ���#7289DA$��0,0,0,5q�6�   ��6D   �� *Key+6�   �� 5r   :   $
��Wrap=�6[   ���#FFFFFF��6D   �� *Value+6o   5s   7   5t   3   5v   +   5w   '   5x   #   5y      5{      5|      5}      5~      5      5�      