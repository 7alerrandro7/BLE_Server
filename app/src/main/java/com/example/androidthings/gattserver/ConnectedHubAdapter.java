package com.example.androidthings.gattserver;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class ConnectedHubAdapter extends ArrayAdapter<ConnectedHub> {
    private final Context context;
    private final ArrayList<ConnectedHub> elementos;

    public ConnectedHubAdapter(Context context, ArrayList<ConnectedHub> elementos){
        super(context, R.layout.auth_users, elementos);
        this.context = context;
        this.elementos = elementos;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View rowView = inflater.inflate(R.layout.auth_users, parent, false);
        TextView text = rowView.findViewById(R.id.users);
        if(elementos.get(position).getHub() != null && elementos.get(position).getTimestamp() != null) {
            int ts = ByteBuffer.wrap(elementos.get(position).getTimestamp()).getInt();
            //text.setText("Cliente: " + elementos.get(position).hub.getName() + " \nTimeStamp: " + new java.util.Date(ts));
            text.setText("Cliente: " + elementos.get(position).getHub().getName() + " \nTimeStamp: " + ts);
        }
        return rowView;
    }

}
